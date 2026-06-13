package store_test

import (
	"path/filepath"
	"testing"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
	"ebpf-agent/internal/store"
)

func TestBaselineSchemaVersionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.db")

	st, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	snaps := []baseline.DimensionSnapshot{
		{Key: aggregator.DimensionKey{MetricName: "exec"}},
	}

	if err := st.SaveBaseline(snaps); err != nil {
		t.Fatal(err)
	}

	loaded, err := st.LoadBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Key.MetricName != "exec" {
		t.Fatalf("unexpected load result: %+v", loaded)
	}
}