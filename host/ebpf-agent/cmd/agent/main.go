package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
	"ebpf-agent/internal/config"
	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/mitre"
	"ebpf-agent/internal/otelexport"
	"ebpf-agent/internal/phase"
	"ebpf-agent/internal/ringbuf"
	"ebpf-agent/internal/scorer"
	"ebpf-agent/internal/store"
	"ebpf-agent/internal/version"
)

import _ "embed"

//go:embed bpf/exec.bpf.o
var bpfProgram []byte

var eventsProcessed atomic.Int64
var ringbufDrops atomic.Int64
var ringbufBPFDrops atomic.Uint64
var enrichmentFailures atomic.Int64
var otelExportErrors atomic.Int64

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	hostID := cfg.Host.ID

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgram))
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating BPF collection: %v", err)
	}
	defer coll.Close()

	populateSuspiciousPorts(coll, cfg.Detection.SuspiciousPorts)

	var tracepoints []link.Link
	for _, tp := range cfg.Tracepoints {
		prog, ok := coll.Programs[tp.Program]
		if !ok {
			log.Printf("WARN: BPF program %q not found, skipping tracepoint %s/%s", tp.Program, tp.Group, tp.Name)
			continue
		}
		l, err := link.Tracepoint(tp.Group, tp.Name, prog, nil)
		if err != nil {
			log.Printf("WARN: failed to attach tracepoint %s/%s: %v", tp.Group, tp.Name, err)
			continue
		}
		tracepoints = append(tracepoints, l)
		log.Printf("Attached tracepoint %s/%s -> %s", tp.Group, tp.Name, tp.Program)
	}
	defer func() {
		for _, tp := range tracepoints {
			tp.Close()
		}
	}()
	if len(tracepoints) == 0 {
		log.Fatalf("no tracepoints attached, exiting")
	}

	ringbufDropsMap := coll.Maps["ringbuf_drops"]

	agentInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ebpf_agent_info",
		Help: "Agent metadata",
	}, []string{"host", "version"})
	agentInfo.WithLabelValues(hostID, version.Version).Set(1)

	baselinePhaseGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "ebpf_baseline_phase",
		Help:        "Current phase: 1=learning, 2=monitoring",
		ConstLabels: prometheus.Labels{"host": hostID},
	})
	baselineProgressGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "ebpf_baseline_progress",
		Help:        "Learning phase progress 0.0 to 1.0",
		ConstLabels: prometheus.Labels{"host": hostID},
	})
	dimensionsNotReadyGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "ebpf_dimensions_not_ready",
		Help:        "Dimensions whose current seasonal bucket is below minimum_samples",
		ConstLabels: prometheus.Labels{"host": hostID},
	})
	eventsProcessedCounter := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name:        "ebpf_events_processed_total",
		Help:        "Total events processed through the pipeline",
		ConstLabels: prometheus.Labels{"host": hostID},
	}, func() float64 { return float64(eventsProcessed.Load()) })

	ringbufDropsCounter := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name:        "ebpf_ringbuf_drops_total",
		Help:        "Events dropped due to userspace channel backpressure",
		ConstLabels: prometheus.Labels{"host": hostID},
	}, func() float64 { return float64(ringbufDrops.Load()) })

	ringbufBPFDropsCounter := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name:        "ebpf_ringbuf_bpf_drops_total",
		Help:        "Events dropped in kernel when bpf_ringbuf_reserve failed",
		ConstLabels: prometheus.Labels{"host": hostID},
	}, func() float64 { return float64(ringbufBPFDrops.Load()) })

	enrichmentFailuresCounter := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name:        "ebpf_enrichment_failures_total",
		Help:        "Events where PID/binary resolution failed",
		ConstLabels: prometheus.Labels{"host": hostID},
	}, func() float64 { return float64(enrichmentFailures.Load()) })

	otelExportErrorsCounter := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name:        "ebpf_otel_export_errors_total",
		Help:        "OTel export shutdown or flush errors",
		ConstLabels: prometheus.Labels{"host": hostID},
	}, func() float64 { return float64(otelExportErrors.Load()) })

	tracepointsAttached := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "ebpf_tracepoints_attached",
		Help:        "Number of active tracepoint attachments",
		ConstLabels: prometheus.Labels{"host": hostID},
	})
	tracepointsAttached.Set(float64(len(tracepoints)))

	prometheus.MustRegister(
		agentInfo, baselinePhaseGauge, baselineProgressGauge, dimensionsNotReadyGauge,
		eventsProcessedCounter, ringbufDropsCounter, ringbufBPFDropsCounter,
		enrichmentFailuresCounter, otelExportErrorsCounter, tracepointsAttached,
	)

	blEngine := baseline.NewEngine(cfg.Baseline.EWMAAlpha, cfg.Scoring.MinimumSamples)

	var st *store.Store
	st, err = store.New(cfg.Baseline.StateFile)
	if err != nil {
		log.Printf("WARN: could not open state store at %s: %v (running without persistence)", cfg.Baseline.StateFile, err)
		st = nil
	}
	if st != nil {
		defer st.Close()
	}

	sc := scorer.New(blEngine, cfg.Scoring.ZScoreThreshold, cfg.Baseline.MinStdDev, cfg.Scoring.ColdStartSeverity,
		cfg.Scoring.Ceilings, cfg.Scoring.MADEnabled)

	otelClient, err := otelexport.Init(context.Background(), cfg.OTel, hostID, cfg.Host.Labels)
	if err != nil {
		log.Fatalf("otel init: %v", err)
	}

	var scoreMu sync.Mutex
	onScore := func(results []scorer.Result, win *aggregator.Window) {
		scoreMu.Lock()
		defer scoreMu.Unlock()
		for _, r := range results {
			if r.Anomaly {
				dim := dimensionLabel(r.Key)
				if r.ColdStart {
					log.Printf("COLD-START [%s] %s/%s new dimension observed (count=%.0f)",
						r.Severity, r.Key.MetricName, dim, r.Observed)
				} else {
					extra := ""
					if r.UsedMAD {
						extra = " (MAD)"
					}
					log.Printf("ANOMALY [%s] %s/%s z=%.2f (mean=%.2f stddev=%.2f observed=%.0f)%s",
						r.Severity, r.Key.MetricName, dim, r.ZScore, r.Mean, r.StdDev, r.Observed, extra)
				}
				if otelClient != nil && win != nil {
					otelClient.EmitAnomaly(context.Background(), r, win)
				}
			}
		}
	}

	phaseMgr := phase.NewManager(
		blEngine, sc, st,
		cfg.Baseline.LearningDuration,
		cfg.Baseline.RecalibrationInterval,
		onScore,
	)

	enrich := enricher.New(cfg.Container.CgroupRoot)
	agg := aggregator.New(
		cfg.Baseline.AggregationWindow,
		cfg.Dimensions.PerUser,
		cfg.Dimensions.PerProcess,
		cfg.Dimensions.PerContainer,
		cfg.Dimensions.Network,
		cfg.Dimensions.FileSystem,
		cfg.Dimensions.Scheduling,
	)

	eventsMap, hasRingbuf := coll.Maps["events"]
	if !hasRingbuf {
		log.Fatal("BPF collection missing ringbuf map \"events\"")
	}
	rbConsumer, err := ringbuf.NewConsumer(eventsMap, 4096)
	if err != nil {
		log.Fatalf("FATAL: failed to create ringbuf consumer: %v", err)
	}
	rbConsumer.SetDropCallback(func() { ringbufDrops.Add(1) })

	var consumerWg sync.WaitGroup
	consumerWg.Add(1)
	go func() {
		defer consumerWg.Done()
		rbConsumer.Run()
	}()
	consumerWg.Add(1)
	go func() {
		defer consumerWg.Done()
		for ev := range rbConsumer.Events() {
			eventsProcessed.Add(1)
			enriched := enrich.Enrich(ev)

			mapping := mitre.Map(enriched)
			for _, t := range mapping.Techniques {
				enriched.MitreTags = append(enriched.MitreTags, t.ID)
			}
			if !enriched.Resolved {
				enrichmentFailures.Add(1)
				log.Printf("ENRICH-FAIL pid=%d comm=%s (process exited before resolution)",
					ev.PID, ev.CommString())
			}

			if otelClient != nil {
				switch enriched.Raw.EventType {
				case ringbuf.EventPtrace, ringbuf.EventCapset:
					otelClient.EmitSecurityEvent(context.Background(), enriched)
				default:
					if enriched.Raw.Flags&(ringbuf.FlagSuspiciousPort|ringbuf.FlagSensitiveFile|ringbuf.FlagPasswdRead) != 0 {
						otelClient.EmitSecurityEvent(context.Background(), enriched)
					}
				}
			}

			agg.Add(enriched)
		}
	}()

	mux := http.NewServeMux()
	handler := promhttp.Handler()
	if cfg.Server.BasicAuth.Enabled {
		handler = basicAuth(handler, cfg.Server.BasicAuth.Username, cfg.Server.BasicAuth.Password)
	}
	mux.Handle(cfg.Server.MetricsPath, handler)

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{Addr: addr, Handler: mux}

	go func() {
		log.Printf("Health endpoint %s on %s", cfg.Server.MetricsPath, addr)
		var srvErr error
		if cfg.Server.TLS.Enabled {
			srvErr = srv.ListenAndServeTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		} else {
			srvErr = srv.ListenAndServe()
		}
		if srvErr != nil && srvErr != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", srvErr)
		}
	}()

	phaseStr := "learning"
	if phaseMgr.Phase() == phase.PhaseMonitoring {
		phaseStr = "monitoring"
	}
	log.Printf("eBPF adaptive agent active — host=%s phase=%s tracepoints=%d version=%s",
		hostID, phaseStr, len(tracepoints), version.Version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	windowTicker := time.NewTicker(cfg.Baseline.AggregationWindow)
	defer windowTicker.Stop()

	healthTicker := time.NewTicker(5 * time.Second)
	defer healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			windowTicker.Stop()
			healthTicker.Stop()
			_ = rbConsumer.Close()
			consumerWg.Wait()
			w := agg.Rotate()
			phaseMgr.ProcessWindow(w)
			phaseMgr.Persist()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if otelClient != nil {
				if err := otelClient.Shutdown(shutdownCtx); err != nil {
					log.Printf("OTel shutdown: %v", err)
					otelExportErrors.Add(1)
				}
			}
			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Printf("HTTP server shutdown: %v", err)
			}
			cancel()
			return

		case <-healthTicker.C:
			baselinePhaseGauge.Set(float64(phaseMgr.Phase()))
			baselineProgressGauge.Set(phaseMgr.Progress())
			now := time.Now()
			dimensionsNotReadyGauge.Set(float64(blEngine.DimensionsNotReady(now.Hour(), int(now.Weekday()))))
			if ringbufDropsMap != nil {
				ringbufBPFDrops.Store(readBPFRingbufDrops(ringbufDropsMap))
			}

		case <-windowTicker.C:
			w := agg.Rotate()
			phaseMgr.ProcessWindow(w)
		}
	}
}

func populateSuspiciousPorts(coll *ebpf.Collection, ports []uint16) {
	m, ok := coll.Maps["suspicious_ports"]
	if !ok {
		return
	}
	val := uint8(1)
	for _, port := range ports {
		if err := m.Put(port, val); err != nil {
			log.Printf("WARN: failed to populate suspicious port %d: %v", port, err)
		}
	}
}

func readBPFRingbufDrops(m *ebpf.Map) uint64 {
	var key uint32
	var values []uint64
	if err := m.Lookup(key, &values); err != nil {
		return ringbufBPFDrops.Load()
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total
}

func dimensionLabel(key aggregator.DimensionKey) string {
	parts := []string{"host"}
	if key.User != "" {
		parts = append(parts, "user:"+key.User)
	}
	if key.Process != "" {
		parts = append(parts, "proc:"+key.Process)
	}
	if key.Container != "" {
		parts = append(parts, "ctr:"+key.Container)
	}
	return strings.Join(parts, ",")
}

func basicAuth(next http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(user), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
