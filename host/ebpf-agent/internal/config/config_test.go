package config

import (
	"os"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	content := `
server:
  port: 9110
  metrics_path: /metrics
tracepoints:
  - group: syscalls
    name: sys_enter_execve
    program: trace_exec
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Port != 9110 {
		t.Errorf("expected port 9110, got %d", cfg.Server.Port)
	}
	if len(cfg.Tracepoints) != 1 {
		t.Errorf("expected 1 tracepoint, got %d", len(cfg.Tracepoints))
	}
	if cfg.Host.ID == "" {
		t.Error("expected host ID to be auto-detected")
	}
	if cfg.Baseline.EWMAAlpha != 0.01 {
		t.Errorf("expected default ewma_alpha 0.01, got %f", cfg.Baseline.EWMAAlpha)
	}
	if cfg.Scoring.ZScoreThreshold != 3.0 {
		t.Errorf("expected default zscore_threshold 3.0, got %f", cfg.Scoring.ZScoreThreshold)
	}
	if cfg.Baseline.MinStdDev != 1.0 {
		t.Errorf("expected default min_stddev 1.0, got %f", cfg.Baseline.MinStdDev)
	}
	if cfg.Scoring.ColdStartSeverity != "warning" {
		t.Errorf("expected default cold_start_severity 'warning', got %s", cfg.Scoring.ColdStartSeverity)
	}
	if cfg.Scoring.MinimumSamples != 15 {
		t.Errorf("expected default minimum_samples 15, got %d", cfg.Scoring.MinimumSamples)
	}
	if len(cfg.Detection.SuspiciousPorts) == 0 {
		t.Error("expected default suspicious_ports")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidPort(t *testing.T) {
	content := `
server:
  port: 99999
tracepoints:
  - group: syscalls
    name: sys_enter_execve
    program: trace_exec
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestLoadNoTracepoints(t *testing.T) {
	content := `
server:
  port: 9110
tracepoints: []
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("expected error for empty tracepoints")
	}
}

func TestLoadInvalidEWMAAlpha(t *testing.T) {
	content := `
server:
  port: 9110
baseline:
  ewma_alpha: 1.5
tracepoints:
  - group: syscalls
    name: sys_enter_execve
    program: trace_exec
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Fatal("expected error for invalid ewma_alpha")
	}
}

func TestLoadWithBaselineConfig(t *testing.T) {
	content := `
server:
  port: 9110
baseline:
  learning_duration: 72h
  ewma_alpha: 0.05
  state_file: /tmp/test-baseline.db
scoring:
  zscore_threshold: 2.5
  minimum_samples: 30
host:
  id: test-host-001
  labels:
    environment: staging
dimensions:
  per_user: false
  per_container: true
tracepoints:
  - group: syscalls
    name: sys_enter_execve
    program: trace_exec
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Host.ID != "test-host-001" {
		t.Errorf("expected host id test-host-001, got %s", cfg.Host.ID)
	}
	if cfg.Baseline.EWMAAlpha != 0.05 {
		t.Errorf("expected ewma_alpha 0.05, got %f", cfg.Baseline.EWMAAlpha)
	}
	if cfg.Scoring.ZScoreThreshold != 2.5 {
		t.Errorf("expected zscore_threshold 2.5, got %f", cfg.Scoring.ZScoreThreshold)
	}
	if cfg.Dimensions.PerUser != false {
		t.Error("expected per_user false")
	}
	if cfg.Dimensions.PerContainer != true {
		t.Error("expected per_container true")
	}
}

func TestLoadWithTLSAndBasicAuth(t *testing.T) {
	content := `
server:
  port: 9110
  metrics_path: /metrics
  tls:
    enabled: true
    cert_file: /path/to/cert.pem
    key_file: /path/to/key.pem
  basic_auth:
    enabled: true
    username: admin
    password: secret
tracepoints:
  - group: syscalls
    name: sys_enter_execve
    program: trace_exec
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.Server.TLS.Enabled {
		t.Error("expected TLS enabled")
	}
	if !cfg.Server.BasicAuth.Enabled {
		t.Error("expected basic auth enabled")
	}
	if cfg.Server.BasicAuth.Username != "admin" {
		t.Errorf("expected username admin, got %s", cfg.Server.BasicAuth.Username)
	}
}
