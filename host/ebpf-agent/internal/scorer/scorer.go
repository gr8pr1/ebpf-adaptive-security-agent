package scorer

import (
	"math"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
)

const skewnessMADThreshold = 1.0

type Result struct {
	Key       aggregator.DimensionKey
	Observed  float64
	Mean      float64
	StdDev    float64
	ZScore    float64
	Anomaly   bool
	Severity  string
	ColdStart bool
	UsedMAD   bool
}

type Scorer struct {
	engine              *baseline.Engine
	threshold           float64
	minStdDev           float64
	coldStartSeverity   string
	madEnabled          bool
	autoSkewness        bool
	ceilings            map[string]float64
}

func New(engine *baseline.Engine, zscoreThreshold, minStdDev float64, coldStartSeverity string,
	ceilings map[string]float64, madEnabled bool,
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
		engine:            engine,
		threshold:         zscoreThreshold,
		minStdDev:         minStdDev,
		coldStartSeverity: coldStartSeverity,
		madEnabled:        madEnabled,
		autoSkewness:      true,
		ceilings:          ceilings,
	}
}

func (s *Scorer) Score(w *aggregator.Window) []Result {
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

		if max, ok := s.ceilings[key.MetricName]; ok && max > 0 && observed > max {
			results = append(results, Result{
				Key:      key,
				Observed: observed,
				Mean:     0,
				StdDev:   0,
				ZScore:   1e6,
				Anomaly:  true,
				Severity: "critical",
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
				Severity:  s.coldStartSeverity,
				ColdStart: true,
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

		var mean, stddev, median, mad float64
		var ready bool
		if useMAD {
			mean, stddev, _, median, mad, ready = s.engine.LookupRobust(key, hour, dow)
		} else {
			mean, stddev, _, ready = s.engine.Lookup(key, hour, dow)
		}

		if !ready {
			continue
		}

		var score float64
		usedMAD := false
		if useMAD && mad > 1e-9 {
			usedMAD = true
			score = 0.6745 * (observed - median) / mad
		} else {
			effStdDev := stddev
			if effStdDev < s.minStdDev {
				effStdDev = s.minStdDev
			}
			score = (observed - mean) / effStdDev
		}

		severity := ""
		isAnomaly := math.Abs(score) > s.threshold
		if isAnomaly {
			severity = "warning"
			if math.Abs(score) > 5.0 {
				severity = "critical"
			}
		}

		results = append(results, Result{
			Key:      key,
			Observed: observed,
			Mean:     mean,
			StdDev:   stddev,
			ZScore:   score,
			Anomaly:  isAnomaly,
			Severity: severity,
			UsedMAD:  usedMAD,
		})
	}

	for dk := range knownDimensions {
		if _, exists := w.Counts[dk]; exists {
			continue
		}
		if s.engine.InFastTrack(dk, w.Start) {
			continue
		}
		mean, stddev, _, ready := s.engine.Lookup(dk, hour, dow)
		if !ready || mean < 1.0 {
			continue
		}

		effStdDev := stddev
		if effStdDev < s.minStdDev {
			effStdDev = s.minStdDev
		}

		zscore := -mean / effStdDev

		if math.Abs(zscore) > s.threshold {
			severity := "warning"
			if math.Abs(zscore) > 5.0 {
				severity = "critical"
			}
			results = append(results, Result{
				Key:      dk,
				Observed: 0,
				Mean:     mean,
				StdDev:   stddev,
				ZScore:   zscore,
				Anomaly:  true,
				Severity: severity,
			})
		}
	}

	return results
}

func (s *Scorer) Threshold() float64 {
	return s.threshold
}

func TimeBucket(t time.Time) (hour, dow int) {
	return t.Hour(), int(t.Weekday())
}
