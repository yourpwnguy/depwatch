package storage_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
	"github.com/yourpwnguy/depwatch/internal/storage"
)

func tempStore(t *testing.T) *storage.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "depwatch_test.db")
	s, err := storage.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStore_RecordAndLatest(t *testing.T) {
	s := tempStore(t)
	now := time.Now()
	entry := &domain.ScanEntry{
		PackageName: "react",
		Ecosystem:   domain.EcosystemNpm,
		Registry:    domain.RegistryNpm,
		Status:      domain.StatusNew,
		Risk:        domain.RiskHigh,
		LastSeen:    now,
		FirstSeen:   now,
	}
	if err := s.RecordEvent(entry); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := s.Latest("react", string(domain.RegistryNpm))
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if got == nil {
		t.Fatal("expected latest entry, got nil")
	}
	if got.Risk != domain.RiskHigh || got.Status != domain.StatusNew {
		t.Fatalf("unexpected stored values: %+v", got)
	}
}

func TestStore_HistoryOrderAndAlerts(t *testing.T) {
	s := tempStore(t)
	now := time.Now()
	// Two observations for the same package; Latest should return the newest.
	for i, risk := range []domain.RiskLevel{domain.RiskLow, domain.RiskHigh} {
		e := &domain.ScanEntry{
			PackageName: "lodash",
			Ecosystem:   domain.EcosystemNpm,
			Registry:    domain.RegistryNpm,
			Status:      domain.StatusChanged,
			Risk:        risk,
			LastSeen:    now.Add(time.Duration(i) * time.Minute),
			FirstSeen:   now,
		}
		if err := s.RecordEvent(e); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	hist, err := s.History("lodash")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("expected 2 history rows, got %d", len(hist))
	}
	if hist[0].Risk != domain.RiskHigh {
		t.Fatalf("expected newest first (HIGH), got %s", hist[0].Risk)
	}

	if err := s.AddAlert(&domain.Alert{
		PackageName: "lodash",
		Registry:    domain.RegistryNpm,
		Risk:        domain.RiskHigh,
		Type:        domain.AlertNewCollision,
		CreatedAt:   now,
	}); err != nil {
		t.Fatalf("add alert: %v", err)
	}
	alerts, err := s.UnresolvedAlerts()
	if err != nil {
		t.Fatalf("alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
}
