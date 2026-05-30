package main

import (
	"log"
	"math"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Scoring constants

const (
	// Base score weights
	wLatency    = 0.3
	wJitter     = 0.7
	jitterScale = 10.0

	// Failure penalties (added to rank - higher = worse)
	currentPenalty  = 500.0 // per active failure
	historicPenalty = 150.0 // per historic failure (lighter - it's in the past)

	// Liveness bonus (subtracted from rank - lower = better)
	// Each successful health check earns a small rank improvement.
	// Capped so that long-lived IPs don't become permanently untouchable.
	livenessPerCheck = 5.0
	maxLiveness      = 150.0

	// EMA smoothing factor for latency / jitter updates.
	// 0.25 → new observations count for 25 %; previous trend counts for 75 %.
	// Dampens transient spikes without ignoring genuine degradation.
	emaAlpha = 0.25

	// Display score ceiling (int, higher = better).
	maxDisplayScore = 10000
)

// computeScore returns the base stability-weighted score (lower = better).
// Returns 1e9 for errored / sentinel (-1) entries.
func computeScore(latency int64, jitter float64) float64 {
	if latency < 0 || jitter < 0 {
		return 1e9
	}
	return wLatency*float64(latency) + wJitter*jitter*jitterScale
}

// emaBlend blends a new observation into a running average.
// First observation (count == 0) is taken as-is; subsequent ones are smoothed.
func emaBlend(prev, next float64, count int) float64 {
	if count == 0 {
		return next
	}
	return emaAlpha*next + (1-emaAlpha)*prev
}

// PoolEntry is a live record inside the active pool (or the history archive).
type PoolEntry struct {
	Addr     string
	Port     int
	Domain   string
	MinRTT   time.Duration
	Latency  int64   // EMA-smoothed latency in ms
	Jitter   float64 // EMA-smoothed jitter
	Download float64

	Score float64 // base score (lower = better); see rank()

	AddedAt     time.Time
	LastChecked time.Time

	FailureCount int // consecutive failures since last insertion; reset on success
	// HistoricFailures accumulates failure counts across all previous eviction
	// cycles. It is intentionally never reset: repeated flapping is a permanent
	// signal about an IP's reliability.
	HistoricFailures int
	CheckCount       int // successful health checks since insertion
}

// rank is the sortable key for all pool decisions (lower = better).
//
//	rank = base_score
//	     + FailureCount    × 500   (strong: IP is failing right now)
//	     + HistoricFailures × 150  (weak:   IP failed in a past cycle)
//	     - min(CheckCount × 5, 150) (liveness bonus: rewarded for staying healthy)
func (e *PoolEntry) rank() float64 {
	liveness := math.Min(float64(e.CheckCount)*livenessPerCheck, maxLiveness)
	return e.Score +
		float64(e.FailureCount)*currentPenalty +
		float64(e.HistoricFailures)*historicPenalty -
		liveness
}

// displayScore converts the internal rank to an integer score where higher
// is better, suitable for JSON API consumers. Range 0–10000.
func (e *PoolEntry) displayScore() int {
	r := e.rank()
	if r >= float64(maxDisplayScore) {
		return 0
	}
	s := maxDisplayScore - int(math.Round(r))
	if s < 0 {
		return 0
	}
	return s
}

func entryFromResult(r ResultRow, historicFailures int) *PoolEntry {
	return &PoolEntry{
		Addr:             r.Addr,
		Port:             r.Port,
		Domain:           r.Domain,
		MinRTT:           r.MinRTT,
		Latency:          r.Latency,
		Jitter:           r.Jitter,
		Download:         r.Download,
		Score:            computeScore(r.Latency, r.Jitter),
		AddedAt:          time.Now(),
		LastChecked:      time.Now(),
		HistoricFailures: historicFailures,
	}
}

type poolEntryResponse struct {
	Addr             string    `json:"addr"`
	Port             int       `json:"port"`
	Domain           string    `json:"domain,omitempty"`
	LatencyMs        int64     `json:"latency_ms"`
	Jitter           float64   `json:"jitter"`
	DownloadBps      float64   `json:"download_bps,omitempty"`
	Score            int       `json:"score"` // higher = better; 0–10000
	AddedAt          time.Time `json:"added_at"`
	LastChecked      time.Time `json:"last_checked"`
	FailureCount     int       `json:"failure_count"`
	HistoricFailures int       `json:"historic_failures"`
	CheckCount       int       `json:"check_count"`
}

func (e *PoolEntry) toResponse() poolEntryResponse {
	return poolEntryResponse{
		Addr:             e.Addr,
		Port:             e.Port,
		Domain:           e.Domain,
		LatencyMs:        e.Latency,
		Jitter:           e.Jitter,
		DownloadBps:      e.Download,
		Score:            e.displayScore(),
		AddedAt:          e.AddedAt,
		LastChecked:      e.LastChecked,
		FailureCount:     e.FailureCount,
		HistoricFailures: e.HistoricFailures,
		CheckCount:       e.CheckCount,
	}
}

// Scan Controller
type ScanController struct {
	mu     sync.Mutex
	cond   *sync.Cond
	paused int32 // atomic: 0 = running, 1 = paused
}

func NewScanController() *ScanController {
	sc := &ScanController{}
	sc.cond = sync.NewCond(&sc.mu)
	return sc
}

func (sc *ScanController) Wait() {
	if atomic.LoadInt32(&sc.paused) == 0 {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for atomic.LoadInt32(&sc.paused) == 1 {
		sc.cond.Wait()
	}
}

func (sc *ScanController) Pause() {
	if atomic.CompareAndSwapInt32(&sc.paused, 0, 1) {
		log.Println("[ScanController] Paused - active pool is full")
	}
}

func (sc *ScanController) Resume() {
	if atomic.CompareAndSwapInt32(&sc.paused, 1, 0) {
		sc.cond.Broadcast()
		log.Println("[ScanController] Resumed - pool needs more IPs")
	}
}

func (sc *ScanController) IsPaused() bool {
	return atomic.LoadInt32(&sc.paused) == 1
}

// Pool Manager

type PoolManager struct {
	mu         sync.RWMutex
	active     map[string]*PoolEntry
	history    []*PoolEntry
	historyMap map[string]*PoolEntry
	config     *HttpServerConfig
	ctrl       *ScanController
}

func NewPoolManager(config *HttpServerConfig, ctrl *ScanController) *PoolManager {
	return &PoolManager{
		active:     make(map[string]*PoolEntry),
		history:    make([]*PoolEntry, 0, config.HistorySize),
		historyMap: make(map[string]*PoolEntry),
		config:     config,
		ctrl:       ctrl,
	}
}

// AddResult ingests a result from the scanner channel.
//
// Stability note: when refreshing an already-active IP, latency and jitter are
// blended with EMA rather than replaced outright. This dampens noise from
// transient measurement spikes without ignoring genuine trends.
func (pm *PoolManager) AddResult(row ResultRow) {
	if row.Err != nil {
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Refresh active entry
	if existing, ok := pm.active[row.Addr]; ok {
		n := existing.CheckCount // use CheckCount as proxy for observation count
		existing.Latency = int64(emaBlend(float64(existing.Latency), float64(row.Latency), n))
		existing.Jitter = emaBlend(existing.Jitter, row.Jitter, n)
		existing.Score = computeScore(existing.Latency, existing.Jitter)
		existing.Port = row.Port
		existing.MinRTT = row.MinRTT
		existing.Download = row.Download
		existing.LastChecked = time.Now()
		pm.syncCtrl()
		return
	}

	// Recover historic failure debt
	historicFailures := 0
	if hist, found := pm.historyMap[row.Addr]; found {
		historicFailures = hist.FailureCount + hist.HistoricFailures
		log.Printf("[Pool] %s returning from history (historic failures: %d)\n",
			row.Addr, historicFailures)
		pm.removeFromHistoryLocked(row.Addr)
	}

	entry := entryFromResult(row, historicFailures)

	if len(pm.active) < pm.config.PoolSize {
		pm.active[row.Addr] = entry
	} else {
		worst := pm.worstLocked()
		if worst != nil && entry.rank() < worst.rank() {
			pm.evictLocked(worst)
			delete(pm.active, worst.Addr)
			pm.active[row.Addr] = entry
		}
	}

	pm.syncCtrl()
}

// IncrementFailure records a health-check failure; evicts on MaxFailures.
func (pm *PoolManager) IncrementFailure(addr string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	e, ok := pm.active[addr]
	if !ok {
		return
	}
	e.FailureCount++
	if e.FailureCount >= pm.config.MaxFailures {
		log.Printf("[Pool] Evicting %s - %d consecutive failures\n", addr, e.FailureCount)
		pm.evictLocked(e)
		delete(pm.active, addr)
		pm.syncCtrl()
	}
}

// UpdateEntry records a successful health check.
// Latency and jitter are EMA-blended for stability.
// HistoricFailures is intentionally NOT reset - it is a permanent record.
func (pm *PoolManager) UpdateEntry(addr string, latency int64, jitter float64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	e, ok := pm.active[addr]
	if !ok {
		return
	}
	e.Latency = int64(emaBlend(float64(e.Latency), float64(latency), e.CheckCount))
	e.Jitter = emaBlend(e.Jitter, jitter, e.CheckCount)
	e.Score = computeScore(e.Latency, e.Jitter)
	e.LastChecked = time.Now()
	e.CheckCount++ // grows the liveness bonus
	e.FailureCount = 0
}

// ActiveSnapshot returns active entries sorted descending by score
func (pm *PoolManager) ActiveSnapshot() []poolEntryResponse {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	entries := make([]*PoolEntry, 0, len(pm.active))
	for _, e := range pm.active {
		cp := *e
		entries = append(entries, &cp)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].rank() < entries[j].rank()
	})

	out := make([]poolEntryResponse, len(entries))
	for i, e := range entries {
		out[i] = e.toResponse()
	}
	return out
}

// HealthCheckBatch selects the next set of IPs to health-check.
//
// When the batch size covers the entire pool, all IPs are returned.
// When the batch is smaller than the pool (the common case), IPs are selected
// randomly so that no IP is systematically skipped across intervals -
// every IP gets a fair and unpredictable share of attention.
func (pm *PoolManager) HealthCheckBatch() []poolEntryResponse {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	all := make([]*PoolEntry, 0, len(pm.active))
	for _, e := range pm.active {
		cp := *e
		all = append(all, &cp)
	}

	n := pm.config.HealthCheckBatchSize
	if n >= len(all) {
		// Full coverage - no selection needed.
		out := make([]poolEntryResponse, len(all))
		for i, e := range all {
			out[i] = e.toResponse()
		}
		return out
	}

	// Partial coverage - random selection for fair distribution.
	rand.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	out := make([]poolEntryResponse, n)
	for i, e := range all[:n] {
		out[i] = e.toResponse()
	}
	return out
}

// internal helpers (callers must hold pm.mu)

func (pm *PoolManager) worstLocked() *PoolEntry {
	var worst *PoolEntry
	for _, e := range pm.active {
		if worst == nil || e.rank() > worst.rank() {
			worst = e
		}
	}
	return worst
}

func (pm *PoolManager) evictLocked(e *PoolEntry) {
	if len(pm.history) >= pm.config.HistorySize {
		oldest := pm.history[0]
		pm.history = pm.history[1:]
		delete(pm.historyMap, oldest.Addr)
	}
	cp := *e
	pm.history = append(pm.history, &cp)
	pm.historyMap[cp.Addr] = pm.history[len(pm.history)-1]
}

func (pm *PoolManager) removeFromHistoryLocked(addr string) {
	delete(pm.historyMap, addr)
	for i, e := range pm.history {
		if e.Addr == addr {
			pm.history = append(pm.history[:i], pm.history[i+1:]...)
			return
		}
	}
}

func (pm *PoolManager) syncCtrl() {
	if pm.ctrl == nil {
		return
	}
	if len(pm.active) >= pm.config.PoolSize {
		pm.ctrl.Pause()
	} else {
		pm.ctrl.Resume()
	}
}

// Health Checker

type scanTargetFn func(ip string, port int, domain, host string, sni *string, scheme string) ResultRow

type HealthChecker struct {
	pool   *PoolManager
	hcConf *HttpServerConfig
	conf   *Conf
	scan   scanTargetFn
	scheme string
}

func NewHealthChecker(
	pool *PoolManager,
	hcConf *HttpServerConfig,
	conf *Conf,
	scan scanTargetFn,
	scheme string,
) *HealthChecker {
	return &HealthChecker{pool: pool, hcConf: hcConf, conf: conf, scan: scan, scheme: scheme}
}

func (hc *HealthChecker) Run() {
	ticker := time.NewTicker(time.Duration(hc.hcConf.HealthCheckSeconds) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		batch := hc.pool.HealthCheckBatch()
		if len(batch) == 0 {
			continue
		}
		log.Printf("[HealthChecker] Checking %d IPs\n", len(batch))
		for _, r := range batch {
			hc.checkEntry(r)
		}
	}
}

func (hc *HealthChecker) checkEntry(r poolEntryResponse) {
	if len(hc.conf.Ports) == 0 {
		return
	}
	sni := hc.conf.TLS.SNI
	row := hc.scan(r.Addr, hc.conf.Ports[0], r.Domain, hc.conf.Hostname, &sni, hc.scheme)

	if row.Err != nil || row.Latency < 0 || row.Jitter < 0 {
		log.Printf("[HealthChecker] %s FAIL (err=%v)\n", r.Addr, row.Err)
		hc.pool.IncrementFailure(r.Addr)
		return
	}
	if hc.conf.Jitter.MaxJitter > 0 && row.Jitter > hc.conf.Jitter.MaxJitter {
		log.Printf("[HealthChecker] %s JITTER (%.2f > %.2f)\n",
			r.Addr, row.Jitter, hc.conf.Jitter.MaxJitter)
		hc.pool.IncrementFailure(r.Addr)
		return
	}
	hc.pool.UpdateEntry(r.Addr, row.Latency, row.Jitter)
}
