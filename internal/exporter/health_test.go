package exporter

import (
	"errors"
	"testing"
	"time"
)

func TestHealthNoTargetsNeverDegraded(t *testing.T) {
	h := NewHealth()
	if h.Degraded(time.Unix(1700000000, 0)) {
		t.Error("Degraded() with no registered targets = true, want false")
	}
}

func TestHealthDuringStartupGrace(t *testing.T) {
	h := NewHealth()
	start := time.Unix(1700000000, 0)
	h.register("site", 10*time.Second, start)

	if h.Degraded(start.Add(20 * time.Second)) {
		t.Error("Degraded() before a target's first round is due = true, want false (startup grace)")
	}
}

func TestHealthDegradedWhenAllTargetsFailing(t *testing.T) {
	h := NewHealth()
	start := time.Unix(1700000000, 0)
	h.register("site", 10*time.Second, start)
	h.register("gateway", 10*time.Second, start)

	h.report("site", errors.New("boom"), start.Add(time.Second))
	h.report("gateway", errors.New("boom"), start.Add(time.Second))

	if !h.Degraded(start.Add(2 * time.Second)) {
		t.Error("Degraded() with every target failing = false, want true")
	}
}

func TestHealthNotDegradedIfOneTargetHealthy(t *testing.T) {
	h := NewHealth()
	start := time.Unix(1700000000, 0)
	h.register("site", 10*time.Second, start)
	h.register("gateway", 10*time.Second, start)

	h.report("site", errors.New("boom"), start.Add(time.Second))
	h.report("gateway", nil, start.Add(time.Second))

	if h.Degraded(start.Add(2 * time.Second)) {
		t.Error("Degraded() with one healthy target = true, want false")
	}
}

func TestHealthDegradedWhenStalled(t *testing.T) {
	h := NewHealth()
	start := time.Unix(1700000000, 0)
	h.register("site", 10*time.Second, start)
	h.report("site", nil, start.Add(time.Second))

	if h.Degraded(start.Add(20 * time.Second)) {
		t.Error("Degraded() within the stall threshold = true, want false")
	}
	if !h.Degraded(start.Add(32 * time.Second)) {
		t.Error("Degraded() past the stall threshold with no new round = false, want true")
	}
}

func TestHealthRecoversAfterSuccess(t *testing.T) {
	h := NewHealth()
	start := time.Unix(1700000000, 0)
	h.register("site", 10*time.Second, start)

	h.report("site", errors.New("boom"), start.Add(time.Second))
	if !h.Degraded(start.Add(2 * time.Second)) {
		t.Error("Degraded() right after a failure = false, want true")
	}

	h.report("site", nil, start.Add(3*time.Second))
	if h.Degraded(start.Add(4 * time.Second)) {
		t.Error("Degraded() after a successful round = true, want false")
	}
}

func TestHealthReportForUnregisteredTargetIsIgnored(t *testing.T) {
	h := NewHealth()
	h.report("ghost", errors.New("boom"), time.Unix(1700000000, 0))

	if h.Degraded(time.Unix(1700000000, 0)) {
		t.Error("Degraded() with only an unregistered report = true, want false")
	}
}

func TestHealthDegradedWhenFirstRoundNeverLands(t *testing.T) {
	h := NewHealth()
	start := time.Unix(1700000000, 0)
	h.register("site", 10*time.Second, start)
	h.register("gateway", 10*time.Second, start)
	h.report("gateway", errors.New("boom"), start.Add(time.Second))

	if h.Degraded(start.Add(30 * time.Second)) {
		t.Error("Degraded() at the end of the startup grace = true, want false")
	}
	if !h.Degraded(start.Add(31 * time.Second)) {
		t.Error("Degraded() with one target never probed past its grace and the other failing = false, want true")
	}

	h.report("site", nil, start.Add(40*time.Second))
	if h.Degraded(start.Add(41 * time.Second)) {
		t.Error("Degraded() after the late target's first success = true, want false")
	}
}
