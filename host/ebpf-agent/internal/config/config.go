package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v2"
)

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type BasicAuthConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type ServerConfig struct {
	Port        int             `yaml:"port"`
	MetricsPath string          `yaml:"metrics_path"`
	TLS         TLSConfig       `yaml:"tls"`
	BasicAuth   BasicAuthConfig `yaml:"basic_auth"`
}

type TracepointConfig struct {
	Group   string `yaml:"group"`
	Name    string `yaml:"name"`
	Program string `yaml:"program"`
}

type BaselineConfig struct {
	LearningDuration       time.Duration `yaml:"learning_duration"`
	AggregationWindow      time.Duration `yaml:"aggregation_window"`
	RecalibrationInterval  time.Duration `yaml:"recalibration_interval"`
	EWMAAlpha              float64       `yaml:"ewma_alpha"`
	MinStdDev              float64       `yaml:"min_stddev"`
	StateFile              string        `yaml:"state_file"`
	NewDimensionLearnWindow time.Duration `yaml:"new_dimension_learn_window"` // fast-track for cold-start dimensions
}

type ScoringConfig struct {
	ZScoreThreshold   float64            `yaml:"zscore_threshold"`
	MinimumSamples    int                `yaml:"minimum_samples"`
	ColdStartSeverity string             `yaml:"cold_start_severity"`
	MADEnabled        bool               `yaml:"mad_enabled"`
	Ceilings          map[string]float64 `yaml:"ceilings"` // per-metric hard caps (observed > ceiling => anomaly)
}

type HostConfig struct {
	ID     string            `yaml:"id"`
	Labels map[string]string `yaml:"labels"`
}

type ContainerConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CgroupRoot string `yaml:"cgroup_root"`
}

type DimensionsConfig struct {
	PerUser      bool `yaml:"per_user"`
	PerProcess   bool `yaml:"per_process"`
	PerContainer bool `yaml:"per_container"`
	Network      bool `yaml:"network"`
	FileSystem   bool `yaml:"filesystem"`
	Scheduling   bool `yaml:"scheduling"`
}

// OTelConfig configures OpenTelemetry export (primary telemetry path).
type OTelConfig struct {
	Enabled              bool              `yaml:"enabled"`
	Endpoint             string            `yaml:"endpoint"`
	Protocol             string            `yaml:"protocol"` // grpc only (http not implemented)
	Insecure             bool              `yaml:"insecure"`
	Headers              map[string]string `yaml:"headers"` // reserved: not applied to gRPC dial yet
	ExportMetrics        bool              `yaml:"export_metrics"`
	ExportTraces         bool              `yaml:"export_traces"`
	ExportLogs           bool              `yaml:"export_logs"`
	MetricExportInterval time.Duration     `yaml:"metric_export_interval"`
	Sampling             map[string]float64 `yaml:"sampling"`
	Batch                OTelBatchConfig   `yaml:"batch"` // reserved: SDK defaults used in otelexport
	ResourceAttributes   map[string]string `yaml:"resource_attributes"`
}

type OTelBatchConfig struct {
	MaxQueueSize     int           `yaml:"max_queue_size"`
	MaxExportBatch   int           `yaml:"max_export_batch"`
	ExportTimeout    time.Duration `yaml:"export_timeout"`
}

type DetectionConfig struct {
	SuspiciousPorts []uint16 `yaml:"suspicious_ports"`
}

type Config struct {
	Server      ServerConfig       `yaml:"server"`
	Tracepoints []TracepointConfig `yaml:"tracepoints"`
	Baseline    BaselineConfig     `yaml:"baseline"`
	Scoring     ScoringConfig      `yaml:"scoring"`
	Host        HostConfig         `yaml:"host"`
	Container   ContainerConfig    `yaml:"container_monitoring"`
	Dimensions  DimensionsConfig   `yaml:"dimensions"`
	Detection   DetectionConfig    `yaml:"detection"`
	OTel        OTelConfig         `yaml:"otel"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{
		Server: ServerConfig{
			Port:        9110,
			MetricsPath: "/metrics",
		},
		Baseline: BaselineConfig{
			LearningDuration:        168 * time.Hour,
			AggregationWindow:       time.Minute,
			RecalibrationInterval:     24 * time.Hour,
			EWMAAlpha:                 0.01,
			MinStdDev:                 1.0,
			StateFile:                 "/var/lib/ebpf-agent/baseline.db",
			NewDimensionLearnWindow:   24 * time.Hour,
		},
		Scoring: ScoringConfig{
			ZScoreThreshold:   3.0,
			MinimumSamples:    15,
			ColdStartSeverity: "warning",
			Ceilings:          map[string]float64{},
		},
		Detection: DetectionConfig{
			SuspiciousPorts: []uint16{4444, 1337, 5555, 6666, 8443, 1234, 31337},
		},
		Container: ContainerConfig{
			CgroupRoot: "/sys/fs/cgroup",
		},
		Dimensions: DimensionsConfig{
			PerUser:      true,
			PerProcess:   true,
			PerContainer: false,
			Network:      true,
			FileSystem:   true,
			Scheduling:   true,
		},
		OTel: OTelConfig{
			Protocol:             "grpc",
			Insecure:             true,
			ExportMetrics:        true,
			ExportTraces:         true,
			ExportLogs:           true,
			MetricExportInterval: 60 * time.Second,
			Batch: OTelBatchConfig{
				MaxQueueSize:   8192,
				MaxExportBatch: 512,
				ExportTimeout:  30 * time.Second,
			},
			Sampling: map[string]float64{
				"ptrace": 1.0, "suspicious_connect": 1.0, "capset": 1.0,
				"sensitive_file": 1.0, "passwd_read": 1.0, "setuid": 1.0, "sudo": 1.0,
				"bind": 0.1, "connect": 0.01, "dns": 0.01, "exec": 0.01,
				"fork": 0, "exit": 0,
			},
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		return nil, fmt.Errorf("invalid port: %d", cfg.Server.Port)
	}

	if len(cfg.Tracepoints) == 0 {
		return nil, fmt.Errorf("no tracepoints defined in config")
	}

	if cfg.Baseline.EWMAAlpha <= 0 || cfg.Baseline.EWMAAlpha >= 1 {
		return nil, fmt.Errorf("ewma_alpha must be in (0, 1), got %f", cfg.Baseline.EWMAAlpha)
	}

	if cfg.Baseline.AggregationWindow <= 0 {
		return nil, fmt.Errorf("aggregation_window must be positive, got %v", cfg.Baseline.AggregationWindow)
	}

	if cfg.Baseline.LearningDuration <= 0 {
		return nil, fmt.Errorf("learning_duration must be positive, got %v", cfg.Baseline.LearningDuration)
	}

	if cfg.Scoring.MinimumSamples <= 0 {
		return nil, fmt.Errorf("minimum_samples must be positive, got %d", cfg.Scoring.MinimumSamples)
	}

	if cfg.Server.BasicAuth.Enabled {
		if strings.TrimSpace(cfg.Server.BasicAuth.Username) == "" || strings.TrimSpace(cfg.Server.BasicAuth.Password) == "" {
			return nil, fmt.Errorf("basic_auth enabled but username or password is empty")
		}
	}

	if cfg.Host.ID == "" {
		cfg.Host.ID = detectHostID()
	}

	if cfg.Scoring.Ceilings == nil {
		cfg.Scoring.Ceilings = map[string]float64{}
	}

	return cfg, nil
}

func detectHostID() string {
	data, err := os.ReadFile("/etc/machine-id")
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id
		}
	}

	hostname, err := os.Hostname()
	if err == nil {
		return hostname
	}

	return "unknown"
}
