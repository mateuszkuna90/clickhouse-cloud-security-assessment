package runner

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mateuszkuna90/clickhouse-cloud-security-assessment/task-03-multicloud-go-scanner/internal/model"
)

type fakeScanner struct {
	p      model.Provider
	scan   func(ctx context.Context) model.ProviderResult
	called atomic.Bool
}

func (f *fakeScanner) Provider() model.Provider { return f.p }
func (f *fakeScanner) Scan(ctx context.Context) model.ProviderResult {
	f.called.Store(true)
	return f.scan(ctx)
}

func ok(p model.Provider) *fakeScanner {
	return &fakeScanner{p: p, scan: func(context.Context) model.ProviderResult {
		return model.ProviderResult{Provider: p, Status: model.ProviderComplete}
	}}
}

func TestRun_OrderAndNil(t *testing.T) {
	got := Run(context.Background(), []Scanner{ok(model.ProviderGCP), nil, ok(model.ProviderAzure), ok(model.ProviderAWS)})
	var order []model.Provider
	for _, r := range got {
		order = append(order, r.Provider)
	}
	want := []model.Provider{model.ProviderAWS, model.ProviderAzure, model.ProviderGCP}
	if len(order) != 3 || order[0] != want[0] || order[1] != want[1] || order[2] != want[2] {
		t.Fatalf("order %v", order)
	}
}

func TestRun_PanicBecomesFailedProvider(t *testing.T) {
	boom := &fakeScanner{p: model.ProviderAWS, scan: func(context.Context) model.ProviderResult {
		panic("DUMMY_SECRET_MARKER in a panic value")
	}}
	got := Run(context.Background(), []Scanner{boom, ok(model.ProviderGCP)})
	if got[0].Status != model.ProviderFailed || got[0].Errors[0].Message != panicMessage ||
		got[0].Errors[0].Operation != OpInternal {
		t.Fatalf("aws result %+v", got[0])
	}
	if got[1].Status != model.ProviderComplete {
		t.Fatalf("gcp must still complete: %+v", got[1])
	}
	if got[0].Scopes == nil || got[0].Diagnostics == nil || got[0].AzureNSGs == nil {
		t.Errorf("failed result must have empty, non-nil slices")
	}
}

func TestRun_MissingOrWrongProviderName(t *testing.T) {
	empty := &fakeScanner{p: model.ProviderGCP, scan: func(context.Context) model.ProviderResult {
		return model.ProviderResult{Status: model.ProviderComplete}
	}}
	wrong := &fakeScanner{p: model.ProviderAzure, scan: func(context.Context) model.ProviderResult {
		return model.ProviderResult{Provider: model.ProviderAWS, Status: model.ProviderComplete}
	}}
	got := Run(context.Background(), []Scanner{empty, wrong})
	if got[0].Provider != model.ProviderAzure || got[1].Provider != model.ProviderGCP ||
		got[1].Status != model.ProviderFailed {
		t.Fatalf("got %+v", got)
	}
}

// Run waits for every scanner; providers run concurrently, and a slow one
// does not delay a cancellation seen by the others.
func TestRun_ConcurrentAndWaitsForAll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var finished atomic.Int32
	slow := func(p model.Provider) *fakeScanner {
		return &fakeScanner{p: p, scan: func(ctx context.Context) model.ProviderResult {
			<-ctx.Done()
			finished.Add(1)
			return model.ProviderResult{Provider: p, Status: model.ProviderFailed}
		}}
	}
	start := time.Now()
	got := Run(ctx, []Scanner{slow(model.ProviderAWS), slow(model.ProviderGCP), slow(model.ProviderAzure)})
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v: providers not concurrent or cancellation not propagated", d)
	}
	if finished.Load() != 3 || len(got) != 3 {
		t.Fatalf("Run returned before every scanner finished: %d/%d", finished.Load(), len(got))
	}
}
