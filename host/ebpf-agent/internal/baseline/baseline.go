package baseline

import (
	"math"
	"sort"
	"sync"
	"time"

	"ebpf-agent/internal/aggregator"
)

// HourlyBuckets is the number of seasonal buckets: 24 hours * 7 days.
const HourlyBuckets = 168

// ObsRingSize is the rolling observation window for robust median/MAD/skewness.
const ObsRingSize = 32

// BucketStats holds running statistics for a single seasonal bucket.
type BucketStats struct {
	Count       int
	Sum         float64
	SumSq       float64
	Min         float64
	Max         float64
	EWMA        float64
	EWMAVar     float64
	FastEWMA    float64
	FastEWMAInit bool
	EWMAInit    bool
	ObsRing     [ObsRingSize]float64
	ObsCount    int
}

func (b *BucketStats) Mean() float64 {
	if b.Count == 0 {
		return 0
	}
	return b.Sum / float64(b.Count)
}

func (b *BucketStats) StdDev() float64 {
	if b.Count < 2 {
		return 0
	}
	mean := b.Mean()
	variance := (b.SumSq / float64(b.Count)) - (mean * mean)
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

func (b *BucketStats) EWMAStdDev() float64 {
	if b.EWMAVar < 0 {
		return 0
	}
	return math.Sqrt(b.EWMAVar)
}

func pushObsRing(ring *[ObsRingSize]float64, count *int, v float64) {
	if *count < ObsRingSize {
		ring[*count] = v
		(*count)++
		return
	}
	copy(ring[:], ring[1:])
	ring[ObsRingSize-1] = v
}

func (b *BucketStats) medianObs() float64 {
	n := b.ObsCount
	if n == 0 {
		return 0
	}
	tmp := make([]float64, n)
	copy(tmp, b.ObsRing[:n])
	sort.Float64s(tmp)
	if n%2 == 1 {
		return tmp[n/2]
	}
	return (tmp[n/2-1] + tmp[n/2]) / 2
}

// MedianAbsDeviation returns MAD of the observation ring vs the median of that ring.
func (b *BucketStats) madObs() float64 {
	n := b.ObsCount
	if n < 2 {
		return 0
	}
	med := b.medianObs()
	dev := make([]float64, n)
	for i := 0; i < n; i++ {
		dev[i] = math.Abs(b.ObsRing[i] - med)
	}
	sort.Float64s(dev)
	if n%2 == 1 {
		return dev[n/2]
	}
	return (dev[n/2-1] + dev[n/2]) / 2
}

// Skewness estimates sample skewness from the observation ring (needs >= 8 samples).
func (b *BucketStats) Skewness() float64 {
	n := b.ObsCount
	if n < 8 {
		return 0
	}
	var sum, sum2, sum3 float64
	for i := 0; i < n; i++ {
		v := b.ObsRing[i]
		sum += v
		sum2 += v * v
		sum3 += v * v * v
	}
	fn := float64(n)
	mean := sum / fn
	variance := sum2/fn - mean*mean
	if variance <= 1e-12 {
		return 0
	}
	stddev := math.Sqrt(variance)
	m3 := sum3/fn - 3*mean*variance - mean*mean*mean
	return m3 / (stddev * stddev * stddev)
}

// DimensionBaseline holds 168 hourly buckets for one metric dimension.
type DimensionBaseline struct {
	Buckets [HourlyBuckets]BucketStats
}

// Engine manages baselines for all dimensions.
type Engine struct {
	alpha                 float64
	fastAlpha             float64
	minSample             int
	fastTrackWindow       time.Duration
	holdHighSeverity      bool
	mu                    sync.RWMutex
	baselines             map[aggregator.DimensionKey]*DimensionBaseline
	fastTrackStarted      map[aggregator.DimensionKey]time.Time
	heldFastTrack         map[aggregator.DimensionKey]struct{}
	heldFastTrackMetrics  map[string]struct{}
	highSeveritySeen      map[aggregator.DimensionKey]struct{}
}

func NewEngine(ewmaAlpha float64, minSamples int) *Engine {
	return &Engine{
		alpha:            ewmaAlpha,
		fastAlpha:        0.1,
		minSample:        minSamples,
		fastTrackWindow:  24 * time.Hour,
		holdHighSeverity: true,
		baselines:        make(map[aggregator.DimensionKey]*DimensionBaseline),
		fastTrackStarted: make(map[aggregator.DimensionKey]time.Time),
		heldFastTrack:        make(map[aggregator.DimensionKey]struct{}),
		heldFastTrackMetrics: make(map[string]struct{}),
		highSeveritySeen:     make(map[aggregator.DimensionKey]struct{}),
	}
}

func (e *Engine) SetFastTrendAlpha(a float64) {
	if a <= 0 || a >= 1 {
		return
	}
	e.mu.Lock()
	e.fastAlpha = a
	e.mu.Unlock()
}

func (e *Engine) SetHoldHighSeverityFastTrack(hold bool) {
	e.mu.Lock()
	e.holdHighSeverity = hold
	e.mu.Unlock()
}

func (e *Engine) SetFastTrackWindow(d time.Duration) {
	if d <= 0 {
		return
	}
	e.mu.Lock()
	e.fastTrackWindow = d
	e.mu.Unlock()
}

func (e *Engine) StartFastTrack(key aggregator.DimensionKey, at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.fastTrackStarted[key]; exists {
		return
	}
	e.fastTrackStarted[key] = at
}

func (e *Engine) InFastTrack(key aggregator.DimensionKey, at time.Time) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	start, ok := e.fastTrackStarted[key]
	if !ok {
		return false
	}
	if at.Sub(start) > e.fastTrackWindow {
		return false
	}
	return true
}

func (e *Engine) ShouldIngestColdStart(key aggregator.DimensionKey, at time.Time) bool {
	if e.InFastTrack(key, at) {
		return !e.isHeldFastTrack(key)
	}
	return false
}

func (e *Engine) isHeldFastTrack(key aggregator.DimensionKey) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if _, held := e.heldFastTrack[key]; held {
		return true
	}
	_, held := e.heldFastTrackMetrics[key.MetricName]
	return held
}

// MarkHighSeverityDimension prevents fast-track ingest for suspicious new dimensions.
func (e *Engine) MarkHighSeverityDimension(key aggregator.DimensionKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.highSeveritySeen[key] = struct{}{}
	if key.MetricName != "" {
		e.heldFastTrackMetrics[key.MetricName] = struct{}{}
	}
	if e.holdHighSeverity {
		e.heldFastTrack[key] = struct{}{}
	}
}

// MarkHighSeverityMetric holds all cold-start dimensions for a metric name.
func (e *Engine) MarkHighSeverityMetric(metric string) {
	if metric == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.heldFastTrackMetrics[metric] = struct{}{}
}

// ClearFastTrackHold removes ingest hold after fast-track window if dimension normalized.
func (e *Engine) ClearFastTrackHold(key aggregator.DimensionKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.heldFastTrack, key)
}

// SeasonalIndex computes the 0–167 bucket from wall clock time.
func SeasonalIndex(hour, dayOfWeek int) int {
	return dayOfWeek*24 + hour
}

func (e *Engine) updateBucket(b *BucketStats, value float64) {
	b.Count++
	b.Sum += value
	b.SumSq += value * value
	if b.Count == 1 || value < b.Min {
		b.Min = value
	}
	if value > b.Max {
		b.Max = value
	}

	if !b.EWMAInit {
		b.EWMA = value
		b.EWMAVar = 0
		b.EWMAInit = true
		b.FastEWMA = value
		b.FastEWMAInit = true
	} else {
		diff := value - b.EWMA
		b.EWMA = e.alpha*value + (1-e.alpha)*b.EWMA
		b.EWMAVar = e.alpha*diff*diff + (1-e.alpha)*b.EWMAVar
		if !b.FastEWMAInit {
			b.FastEWMA = value
			b.FastEWMAInit = true
		} else {
			b.FastEWMA = e.fastAlpha*value + (1-e.fastAlpha)*b.FastEWMA
		}
	}

	pushObsRing(&b.ObsRing, &b.ObsCount, value)
}

// Ingest adds a window's data points to the baseline.
func (e *Engine) Ingest(w *aggregator.Window) {
	e.IngestFiltered(w, nil)
}

// IngestFiltered ingests window counts, skipping keys in skip.
func (e *Engine) IngestFiltered(w *aggregator.Window, skip map[aggregator.DimensionKey]struct{}) {
	hour := w.Start.Hour()
	dow := int(w.Start.Weekday())
	idx := SeasonalIndex(hour, dow)

	e.mu.Lock()
	defer e.mu.Unlock()

	for key, value := range w.Counts {
		if skip != nil {
			if _, excluded := skip[key]; excluded {
				continue
			}
		}

		bl, ok := e.baselines[key]
		if !ok {
			bl = &DimensionBaseline{}
			e.baselines[key] = bl
		}

		e.updateBucket(&bl.Buckets[idx], value)
	}
}

type LookupResult struct {
	Mean      float64
	StdDev    float64
	EWMA      float64
	FastEWMA  float64
	Ready     bool
	Confidence float64 // 0..1 bucket sample confidence
}

func (e *Engine) bucketAt(bl *DimensionBaseline, idx int) *BucketStats {
	if idx < 0 || idx >= HourlyBuckets {
		return nil
	}
	return &bl.Buckets[idx]
}

func (e *Engine) lookupBucket(b *BucketStats) LookupResult {
	if b == nil || b.Count < e.minSample || !b.EWMAInit {
		return LookupResult{Ready: false}
	}
	stddev := b.EWMAStdDev()
	if stddev <= 0 {
		stddev = b.StdDev()
	}
	conf := float64(b.Count) / float64(e.minSample*3)
	if conf > 1 {
		conf = 1
	}
	return LookupResult{
		Mean:       b.EWMA,
		StdDev:     stddev,
		EWMA:       b.EWMA,
		FastEWMA:   b.FastEWMA,
		Ready:      true,
		Confidence: conf,
	}
}

func (e *Engine) globalFallback(bl *DimensionBaseline) LookupResult {
	var sumMean, sumStd, sumEWMA, sumFast float64
	var count int
	var totalSamples int
	for i := range bl.Buckets {
		b := &bl.Buckets[i]
		totalSamples += b.Count
		if res := e.lookupBucket(b); res.Ready {
			sumMean += res.Mean
			sumStd += res.StdDev
			sumEWMA += res.EWMA
			sumFast += res.FastEWMA
			count++
		}
	}
	if count == 0 {
		return LookupResult{Ready: false}
	}
	f := float64(count)
	conf := float64(totalSamples) / float64(e.minSample*HourlyBuckets)
	if conf > 1 {
		conf = 1
	}
	return LookupResult{
		Mean:       sumMean / f,
		StdDev:     sumStd / f,
		EWMA:       sumEWMA / f,
		FastEWMA:   sumFast / f,
		Ready:      true,
		Confidence: conf * 0.5,
	}
}

func neighborIndices(idx int) []int {
	neighbors := []int{idx - 1, idx + 1, idx - 24, idx + 24}
	var out []int
	for _, n := range neighbors {
		if n >= 0 && n < HourlyBuckets {
			out = append(out, n)
		}
	}
	return out
}

func (e *Engine) lookupWithFallback(bl *DimensionBaseline, idx int) LookupResult {
	if res := e.lookupBucket(e.bucketAt(bl, idx)); res.Ready {
		return res
	}

	var sumMean, sumStd, sumEWMA, sumFast float64
	var count int
	for _, n := range neighborIndices(idx) {
		if res := e.lookupBucket(e.bucketAt(bl, n)); res.Ready {
			sumMean += res.Mean
			sumStd += res.StdDev
			sumEWMA += res.EWMA
			sumFast += res.FastEWMA
			count++
		}
	}
	if count == 0 {
		return e.globalFallback(bl)
	}
	f := float64(count)
	conf := float64(count) / 4.0
	if conf > 1 {
		conf = 1
	}
	return LookupResult{
		Mean:       sumMean / f,
		StdDev:     sumStd / f,
		EWMA:       sumEWMA / f,
		FastEWMA:   sumFast / f,
		Ready:      true,
		Confidence: conf * 0.75,
	}
}

// Lookup returns EWMA-blended stats for a dimension at a given seasonal index.
func (e *Engine) Lookup(key aggregator.DimensionKey, hour, dow int) (mean, stddev, ewma, fastEWMA float64, confidence float64, ready bool) {
	idx := SeasonalIndex(hour, dow)

	e.mu.RLock()
	defer e.mu.RUnlock()

	bl, ok := e.baselines[key]
	if !ok {
		return 0, 0, 0, 0, 0, false
	}

	res := e.lookupWithFallback(bl, idx)
	return res.Mean, res.StdDev, res.EWMA, res.FastEWMA, res.Confidence, res.Ready
}

// LookupRobust returns EWMA stats plus median/MAD from the observation ring.
func (e *Engine) LookupRobust(key aggregator.DimensionKey, hour, dow int) (mean, stddev, ewma, fastEWMA, median, mad float64, confidence float64, ready bool) {
	idx := SeasonalIndex(hour, dow)

	e.mu.RLock()
	defer e.mu.RUnlock()

	bl, ok := e.baselines[key]
	if !ok {
		return 0, 0, 0, 0, 0, 0, 0, false
	}

	b := e.bucketAt(bl, idx)
	if b != nil {
		median = b.medianObs()
		mad = b.madObs()
	}

	res := e.lookupWithFallback(bl, idx)
	return res.Mean, res.StdDev, res.EWMA, res.FastEWMA, median, mad, res.Confidence, res.Ready
}

// LookupSkewness returns sample skewness for the seasonal bucket observation ring.
func (e *Engine) LookupSkewness(key aggregator.DimensionKey, hour, dow int) float64 {
	idx := SeasonalIndex(hour, dow)
	e.mu.RLock()
	defer e.mu.RUnlock()
	bl, ok := e.baselines[key]
	if !ok {
		return 0
	}
	b := e.bucketAt(bl, idx)
	if b == nil {
		return 0
	}
	return b.Skewness()
}
func (e *Engine) AllDimensions() []aggregator.DimensionKey {
	e.mu.RLock()
	defer e.mu.RUnlock()

	keys := make([]aggregator.DimensionKey, 0, len(e.baselines))
	for k := range e.baselines {
		keys = append(keys, k)
	}
	return keys
}

// DimensionsNotReady counts dimension keys whose current seasonal bucket is below minimum_samples.
func (e *Engine) DimensionsNotReady(hour, dow int) int {
	idx := SeasonalIndex(hour, dow)

	e.mu.RLock()
	defer e.mu.RUnlock()

	notReady := 0
	for _, bl := range e.baselines {
		b := e.bucketAt(bl, idx)
		if b == nil || b.Count < e.minSample {
			notReady++
		}
	}
	return notReady
}

// TotalSamples returns the total number of windows ingested across
// all buckets for a dimension.
func (e *Engine) TotalSamples(key aggregator.DimensionKey) int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	bl, ok := e.baselines[key]
	if !ok {
		return 0
	}

	total := 0
	for i := range bl.Buckets {
		total += bl.Buckets[i].Count
	}
	return total
}

// Snapshot returns a copy of the entire baseline state for persistence.
type DimensionSnapshot struct {
	Key     aggregator.DimensionKey
	Buckets [HourlyBuckets]BucketStats
}

func (e *Engine) Snapshot() []DimensionSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	snaps := make([]DimensionSnapshot, 0, len(e.baselines))
	for k, bl := range e.baselines {
		snaps = append(snaps, DimensionSnapshot{
			Key:     k,
			Buckets: bl.Buckets,
		})
	}
	return snaps
}

// Restore loads a snapshot back into the engine.
func (e *Engine) Restore(snaps []DimensionSnapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, s := range snaps {
		bl := &DimensionBaseline{Buckets: s.Buckets}
		for i := range bl.Buckets {
			b := &bl.Buckets[i]
			if b.Count > 0 && !b.EWMAInit {
				b.EWMA = b.Mean()
				sd := b.StdDev()
				b.EWMAVar = sd * sd
				b.EWMAInit = true
				b.FastEWMA = b.EWMA
				b.FastEWMAInit = true
			}
		}
		e.baselines[s.Key] = bl
	}
}
