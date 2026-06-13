package scorer

import (
	"math"
	"strings"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
	"ebpf-agent/internal/config"
)

const skewnessMADThreshold = 1.0

type Result struct {
	Key        aggregator.DimensionKey
	Observed   float64
	Mean       float64
	StdDev     float64
	ZScore     float64
	Anomaly    bool
	Severity   string
	ColdStart  bool
	UsedMAD    bool
	Confidence float64
}

type Scorer struct {
	engine              *baseline.Engine
	threshold           float64
	minStdDev           float64
	coldStartSeverity   string
	madEnabled          bool
	autoSkewness        bool
	ceilings            map[string]float64
	ceilingMultiplier   float64
	maintenanceWindows  []config.MaintenanceWindowConfig
}

func New(engine *baseline.Engine, zscoreThreshold, minStdDev float64, coldStartSeverity string,
	ceilings map[string]float64, madEnabled bool, ceilingMultiplier float64,
	maintenance []config.MaintenanceWindowConfig,
) *Scorer {
	if minStdDev <= 0 {
		minStdDev = 1.0
	}
	if coldStartSeverity == "" {
		coldStartSeverity = "warning"
	}
	if ceilings == nil {
		ceilings = map[string]float64{}
	}
	return &Scorer{
		engine:             engine,
		threshold:          zscoreThreshold,
		minStdDev:          minStdDev,
		coldStartSeverity:  coldStartSeverity,
		madEnabled:         madEnabled,
		autoSkewness:       true,
		ceilings:           ceilings,
		ceilingMultiplier:  ceilingMultiplier,
		maintenanceWindows: maintenance,
	}
}

func (s *Scorer) Score(w *aggregator.Window) []Result {
	if s.inMaintenanceWindow(w.Start) {
		return nil
	}

	hour := w.Start.Hour()
	dow := int(w.Start.Weekday())

	var results []Result

	knownDimensions := make(map[aggregator.DimensionKey]struct{})
	for _, dk := range s.engine.AllDimensions() {
		knownDimensions[dk] = struct{}{}
	}

	for key, observed := range w.Counts {
		_, known := knownDimensions[key]
		if s.engine.InFastTrack(key, w.Start) && known {
			continue
		}

		if s.ceilingTriggered(key, observed, hour, dow) {
			conf := s.bucketConfidence(key, hour, dow)
			results = append(results, Result{
				Key:        key,
				Observed:   observed,
				Anomaly:    true,
				Severity:   s.severityFromConfidence("warning", conf, false),
				Confidence: conf,
			})
			continue
		}

		if _, known := knownDimensions[key]; !known {
			if s.engine.InFastTrack(key, w.Start) {
				continue
			}
			s.engine.StartFastTrack(key, w.Start)
			results = append(results, Result{
				Key:       key,
				Observed:  observed,
				Anomaly:   true,
				Severity:  s.adjustColdStartSeverity(s.coldStartSeverity),
				ColdStart: true,
				Confidence: 0,
			})
			continue
		}

		useMAD := s.madEnabled
		if s.autoSkewness {
			skew := math.Abs(s.engine.LookupSkewness(key, hour, dow))
			if skew > skewnessMADThreshold {
				useMAD = true
			}
		}

		var mean, stddev, median, mad, fastEWMA, confidence float64
		var ready bool
		if useMAD {
			mean, stddev, _, fastEWMA, median, mad, confidence, ready = s.engine.LookupRobust(key, hour, dow)
		} else {
			var ewma float64
			mean, stddev, ewma, fastEWMA, confidence, ready = s.engine.Lookup(key, hour, dow)
			_ = ewma
		}

		if !ready {
			continue
		}

		detrended := observed
		if fastEWMA > 0 {
			detrended = observed - (fastEWMA - mean)
		}

		var score float64
		usedMAD := false
		if useMAD && mad > 1e-9 {
			usedMAD = true
			score = 0.6745 * (detrended - median) / mad
		} else {
			effStdDev := stddev
			if effStdDev < s.minStdDev {
				effStdDev = s.minStdDev
			}
			score = (detrended - mean) / effStdDev
		}

		severity := ""
		isAnomaly := math.Abs(score) > s.threshold
		if isAnomaly {
			base := "warning"
			if math.Abs(score) > 5.0 {
				base = "critical"
			}
			severity = s.severityFromConfidence(base, confidence, false)
		}

		results = append(results, Result{
			Key:        key,
			Observed:   observed,
			Mean:       mean,
			StdDev:     stddev,
			ZScore:     score,
			Anomaly:    isAnomaly,
			Severity:   severity,
			UsedMAD:    usedMAD,
			Confidence: confidence,
		})
	}

	for dk := range knownDimensions {
		if _, exists := w.Counts[dk]; exists {
			continue
		}
		if s.engine.InFastTrack(dk, w.Start) {
			continue
		}
		mean, stddev, _, _, confidence, ready := s.engine.Lookup(dk, hour, dow)
		if !ready || mean < 1.0 {
			continue
		}

		effStdDev := stddev
		if effStdDev < s.minStdDev {
			effStdDev = s.minStdDev
		}

		zscore := -mean / effStdDev

		if math.Abs(zscore) > s.threshold {
			base := "warning"
			if math.Abs(zscore) > 5.0 {
				base = "critical"
			}
			results = append(results, Result{
				Key:        dk,
				Observed:   0,
				Mean:       mean,
				StdDev:     stddev,
				ZScore:     zscore,
				Anomaly:    true,
				Severity:   s.severityFromConfidence(base, confidence, false),
				Confidence: confidence,
			})
		}
	}

	return results
}

func (s *Scorer) ceilingTriggered(key aggregator.DimensionKey, observed float64, hour, dow int) bool {
	if ceiling, ok := s.ceilings[key.MetricName]; ok && ceiling > 0 && observed > ceiling {
		return true
	}
	if s.ceilingMultiplier > 0 {
		mean, _, _, _, _, ready := s.engine.Lookup(key, hour, dow)
		if ready && mean > 0 && observed > mean*s.ceilingMultiplier {
			return true
		}
	}
	return false
}

func (s *Scorer) bucketConfidence(key aggregator.DimensionKey, hour, dow int) float64 {
	_, _, _, _, conf, ready := s.engine.Lookup(key, hour, dow)
	if !ready {
		return 0
	}
	return conf
}

func (s *Scorer) severityFromConfidence(base string, confidence float64, coldStart bool) string {
	if coldStart {
		return s.adjustColdStartSeverity(base)
	}
	if confidence < 0.35 {
		if base == "critical" {
			return "warning"
		}
		return "info"
	}
	if confidence < 0.6 && base == "critical" {
		return "warning"
	}
	return base
}

func (s *Scorer) adjustColdStartSeverity(sev string) string {
	return "info"
}

func (s *Scorer) inMaintenanceWindow(t time.Time) bool {
	if len(s.maintenanceWindows) == 0 {
		return false
	}
	day := strings.ToLower(t.Weekday().String())[:3]
	hour := t.Hour()
	for _, w := range s.maintenanceWindows {
		if !windowDayMatch(w.Days, day) {
			continue
		}
		if hour >= w.StartHour && hour < w.EndHour {
			return true
		}
	}
	return false
}

func windowDayMatch(days []string, day string) bool {
	for _, d := range days {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "*" || d == day {
			return true
		}
	}
	return false
}

func (s *Scorer) Threshold() float64 {
	return s.threshold
}

func TimeBucket(t time.Time) (hour, dow int) {
	return t.Hour(), int(t.Weekday())
}
