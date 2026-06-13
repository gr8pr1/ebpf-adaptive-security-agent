// Package otelexport provides OpenTelemetry export for anomaly traces, security logs, and metrics.
package otelexport

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/config"
	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
	"ebpf-agent/internal/scorer"
	"ebpf-agent/internal/version"
)

// Client holds OTel providers and emit helpers.
type Client struct {
	tracer        trace.Tracer
	logger        log.Logger
	shutdownFuncs []func(context.Context) error
	cfg           config.OTelConfig
	sampling      map[string]float64
}

// Init builds tracer, meter, and log providers from config.
func Init(ctx context.Context, cfg config.OTelConfig, hostID string, hostLabels map[string]string) (*Client, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("otel: endpoint is required when enabled")
	}
	proto := strings.ToLower(strings.TrimSpace(cfg.Protocol))
	if proto == "" {
		proto = "grpc"
	}
	if proto != "grpc" {
		return nil, fmt.Errorf("otel: protocol %q is not supported (only grpc OTLP is implemented)", cfg.Protocol)
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String("ebpf-agent"),
		semconv.ServiceVersionKey.String(version.Version),
		attribute.String("host.id", hostID),
		attribute.String("host.name", hostID),
	}
	if hostLabels != nil {
		if v := hostLabels["environment"]; v != "" {
			attrs = append(attrs, attribute.String("deployment.environment", v))
		}
		if v := hostLabels["role"]; v != "" {
			attrs = append(attrs, attribute.String("host.role", v))
		}
	}
	for k, v := range cfg.ResourceAttributes {
		if v != "" {
			attrs = append(attrs, attribute.String(k, v))
		}
	}

	res, err := resource.New(ctx, resource.WithAttributes(attrs...))
	if err != nil {
		return nil, err
	}

	dialOpts := []grpc.DialOption{}
	if cfg.Insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	c := &Client{cfg: cfg, sampling: cfg.Sampling}
	if c.sampling == nil {
		c.sampling = map[string]float64{}
	}

	batchOpts := []sdktrace.BatchSpanProcessorOption{}
	if cfg.Batch.MaxQueueSize > 0 {
		batchOpts = append(batchOpts, sdktrace.WithMaxQueueSize(cfg.Batch.MaxQueueSize))
	}
	if cfg.Batch.MaxExportBatch > 0 {
		batchOpts = append(batchOpts, sdktrace.WithMaxExportBatchSize(cfg.Batch.MaxExportBatch))
	}
	if cfg.Batch.ExportTimeout > 0 {
		batchOpts = append(batchOpts, sdktrace.WithBatchTimeout(cfg.Batch.ExportTimeout))
	}

	if cfg.ExportTraces {
		texp, err := otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(cfg.Endpoint),
			otlptracegrpc.WithDialOption(dialOpts...),
		)
		if err != nil {
			return nil, fmt.Errorf("otel trace exporter: %w", err)
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(texp, batchOpts...),
			sdktrace.WithResource(res),
		)
		otel.SetTracerProvider(tp)
		c.tracer = tp.Tracer("ebpf-agent")
		c.shutdownFuncs = append(c.shutdownFuncs, tp.Shutdown)
	}

	if cfg.ExportMetrics {
		mexp, err := otlpmetricgrpc.New(ctx,
			otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
			otlpmetricgrpc.WithDialOption(dialOpts...),
		)
		if err != nil {
			return nil, fmt.Errorf("otel metric exporter: %w", err)
		}
		mp := metric.NewMeterProvider(
			metric.WithReader(metric.NewPeriodicReader(mexp, metric.WithInterval(cfg.MetricExportInterval))),
			metric.WithResource(res),
		)
		otel.SetMeterProvider(mp)
		c.shutdownFuncs = append(c.shutdownFuncs, mp.Shutdown)
	}

	if cfg.ExportLogs {
		lexp, err := otlploggrpc.New(ctx,
			otlploggrpc.WithEndpoint(cfg.Endpoint),
			otlploggrpc.WithDialOption(dialOpts...),
		)
		if err != nil {
			return nil, fmt.Errorf("otel log exporter: %w", err)
		}
		logBatchOpts := []sdklog.BatchProcessorOption{}
		if cfg.Batch.MaxQueueSize > 0 {
			logBatchOpts = append(logBatchOpts, sdklog.WithMaxQueueSize(cfg.Batch.MaxQueueSize))
		}
		if cfg.Batch.MaxExportBatch > 0 {
			logBatchOpts = append(logBatchOpts, sdklog.WithExportMaxBatchSize(cfg.Batch.MaxExportBatch))
		}
		if cfg.Batch.ExportTimeout > 0 {
			logBatchOpts = append(logBatchOpts, sdklog.WithExportTimeout(cfg.Batch.ExportTimeout))
		}
		lp := sdklog.NewLoggerProvider(
			sdklog.WithProcessor(sdklog.NewBatchProcessor(lexp, logBatchOpts...)),
			sdklog.WithResource(res),
		)
		global.SetLoggerProvider(lp)
		c.logger = lp.Logger("ebpf-agent")
		c.shutdownFuncs = append(c.shutdownFuncs, lp.Shutdown)
	}

	return c, nil
}

// EmitAnomaly records an anomaly as a span (when tracing export is enabled).
func (c *Client) EmitAnomaly(ctx context.Context, r scorer.Result, w *aggregator.Window) {
	if c == nil || c.tracer == nil {
		return
	}
	_, span := c.tracer.Start(ctx, "anomaly."+r.Key.MetricName,
		trace.WithAttributes(
			attribute.String("ebpf.anomaly.metric", r.Key.MetricName),
			attribute.String("ebpf.anomaly.dimension.user", r.Key.User),
			attribute.String("ebpf.anomaly.dimension.process", r.Key.Process),
			attribute.String("ebpf.anomaly.dimension.container", r.Key.Container),
			attribute.Float64("ebpf.anomaly.observed", r.Observed),
			attribute.Float64("ebpf.anomaly.baseline_mean", r.Mean),
			attribute.Float64("ebpf.anomaly.baseline_stddev", r.StdDev),
			attribute.Float64("ebpf.anomaly.zscore", r.ZScore),
			attribute.Bool("ebpf.anomaly.used_mad", r.UsedMAD),
			attribute.String("ebpf.anomaly.severity", r.Severity),
			attribute.String("ebpf.anomaly.window_start", w.Start.Format(time.RFC3339)),
			attribute.String("ebpf.anomaly.window_end", w.End.Format(time.RFC3339)),
		))
	span.End()
}

// EmitSecurityEvent exports a high-value security event as a LogRecord (and optional trace span).
func (c *Client) EmitSecurityEvent(ctx context.Context, ev *enricher.EnrichedEvent) {
	if c == nil {
		return
	}
	rate := SampleRate(c.sampling, ev.Raw.EventType, ev.Raw.Flags)
	if rate <= 0 {
		return
	}
	if rate < 1.0 && !shouldSample(ev.Raw.TimestampNs, rate) {
		return
	}

	if c.logger != nil {
		var rec log.Record
		rec.SetTimestamp(time.Now())
		rec.SetBody(log.StringValue("security.event"))
		rec.SetSeverity(log.SeverityInfo)
		rec.AddAttributes(
			log.Int("ebpf.event.type_id", int(ev.Raw.EventType)),
			log.String("ebpf.event.comm", ev.Raw.CommString()),
			log.String("ebpf.event.binary", ev.Binary),
			log.String("ebpf.event.dest_ip", ev.Raw.FormatDestIP()),
			log.Int("ebpf.event.dest_port", int(ev.Raw.DestPort)),
			log.Int("ebpf.event.ppid", int(ev.Raw.PPID)),
		)
		if len(ev.MitreTags) > 0 {
			rec.AddAttributes(log.String("mitre.technique.ids", strings.Join(ev.MitreTags, ",")))
		}
		c.logger.Emit(ctx, rec)
	}

	if c.tracer != nil {
		attrs := []attribute.KeyValue{
			attribute.Int("ebpf.event.type_id", int(ev.Raw.EventType)),
			attribute.String("ebpf.event.comm", ev.Raw.CommString()),
			attribute.String("ebpf.event.binary", ev.Binary),
			attribute.String("ebpf.event.dest_ip", ev.Raw.FormatDestIP()),
			attribute.Int("ebpf.event.dest_port", int(ev.Raw.DestPort)),
			attribute.Int("ebpf.event.ppid", int(ev.Raw.PPID)),
		}
		if len(ev.MitreTags) > 0 {
			attrs = append(attrs, attribute.String("mitre.technique.ids", strings.Join(ev.MitreTags, ",")))
		}
		_, span := c.tracer.Start(ctx, "security.event", trace.WithAttributes(attrs...))
		span.End()
	}
}

// EmitChainSpan emits a parent/child kill-chain span.
func (c *Client) EmitChainSpan(ctx context.Context, parent trace.SpanContext, name string, attrs []attribute.KeyValue) {
	if c == nil || c.tracer == nil {
		return
	}
	opts := []trace.SpanStartOption{trace.WithAttributes(attrs...)}
	if parent.IsValid() {
		opts = append(opts, trace.WithLinks(trace.Link{SpanContext: parent}))
	}
	_, span := c.tracer.Start(ctx, name, opts...)
	span.End()
}

func shouldSample(timestampNs uint64, rate float64) bool {
	bucket := int(timestampNs % 1000)
	return bucket < int(rate*1000)
}

// SampleRate resolves the sampling rate for an event type and flags.
func SampleRate(m map[string]float64, eventType uint8, flags uint8) float64 {
	key := samplingKey(eventType, flags)
	if r, ok := m[key]; ok {
		return r
	}
	return 0.01
}

func samplingKey(eventType uint8, flags uint8) string {
	switch eventType {
	case ringbuf.EventPtrace:
		return "ptrace"
	case ringbuf.EventConnect:
		if flags&ringbuf.FlagSuspiciousPort != 0 {
			return "suspicious_connect"
		}
		return "connect"
	case ringbuf.EventBind:
		return "bind"
	case ringbuf.EventDNS:
		return "dns"
	case ringbuf.EventOpenat:
		if flags&ringbuf.FlagPasswdRead != 0 {
			return "passwd_read"
		}
		if flags&ringbuf.FlagSensitiveFile != 0 {
			return "sensitive_file"
		}
		return "file_open"
	case ringbuf.EventExec:
		if flags&ringbuf.FlagSudo != 0 {
			return "sudo"
		}
		if flags&ringbuf.FlagPasswdRead != 0 {
			return "passwd_read"
		}
		return "exec"
	case ringbuf.EventSetuid:
		return "setuid"
	case ringbuf.EventSetgid:
		return "setgid"
	case ringbuf.EventCapset:
		return "capset"
	case ringbuf.EventFork:
		return "fork"
	case ringbuf.EventExit:
		return "exit"
	default:
		return "exec"
	}
}

// Shutdown flushes and shuts down all providers.
func (c *Client) Shutdown(ctx context.Context) error {
	if c == nil {
		return nil
	}
	var first error
	for _, fn := range c.shutdownFuncs {
		if e := fn(ctx); e != nil && first == nil {
			first = e
		}
	}
	return first
}
