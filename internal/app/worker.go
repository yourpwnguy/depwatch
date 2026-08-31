package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yourpwnguy/depwatch/internal/domain"
	"github.com/yourpwnguy/depwatch/internal/registry"
)

type job struct {
	pkg domain.InternalPackage
	reg registry.Registry
}

type result struct {
	entry *domain.ScanEntry
	err   error
	reg   domain.RegistryName
	pkg   string
}

// scanPipeline runs collision detection across all (package, registry) pairs using
// a bounded worker pool. It returns one ScanEntry per pair. Registry errors are
// captured as partial results (err != nil) rather than failing the whole scan, so
// a single unavailable registry degrades gracefully instead of aborting.
//
// Concurrency model: a fixed job channel is filled by the enqueuer, then
// cfg.Scan.Workers goroutines pull jobs, query, detect, and analyze. A collector
// drains results after all workers finish. Context cancellation stops new work and
// unblocks waiting workers via their HTTP request contexts.
func (a *App) scanPipeline(ctx context.Context, pkgs []domain.InternalPackage, opts ScanOptions) (*domain.ScanResult, error) {
	total := len(pkgs) * len(a.regs)
	jobs := make(chan job, total)
	results := make(chan result, total)

	go func() {
		defer close(jobs)
		for _, p := range pkgs {
			for _, r := range a.regs {
				// A package is only queried against the registry matching its
				// ecosystem, unless AllRegistries was requested (the `package`
				// investigation command). Querying an npm name against crates.io for
				// example returns 400 and would pollute results with false errors.
				if !opts.AllRegistries && domain.Ecosystem(r.Name()) != p.Ecosystem {
					continue
				}
				jobs <- job{pkg: p, reg: r}
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < a.cfg.Scan.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, jobs, results, a, opts.Progress)
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	res := &domain.ScanResult{StartedAt: time.Now()}
	done := 0
	for r := range results {
		done++
		if opts.Progress != nil {
			// The collector only knows the final verdict per job, so it emits the
			// terminal event here (done or error). The querying/analyzing transitions
			// are emitted down in scanOne where the work actually happens.
			if r.err != nil {
				opts.Progress(domain.ProgressEvent{Package: r.pkg, Registry: r.reg, Phase: domain.PhaseError, Error: r.err.Error()})
			} else {
				opts.Progress(domain.ProgressEvent{
					Package:   r.pkg,
					Registry:  r.reg,
					Phase:     domain.PhaseDone,
					Status:    r.entry.Status,
					Risk:      r.entry.Risk,
					Signals:   r.entry.Signals,
					Threat:    r.entry.Threat,
					Collision: r.entry.Collision,
					FirstSeen: r.entry.FirstSeen,
				})
			}
		}
		if r.err != nil {
			res.Partial = true
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %s", r.reg, r.err))
			continue
		}
		res.Entries = append(res.Entries, *r.entry)
	}
	return res, nil
}

// worker processes jobs until the channel is closed. Each job queries one registry
// for one package; absence of a public package is recorded as SAFE. progress, when
// non-nil, receives phase events for the live renderer.
func worker(ctx context.Context, jobs <-chan job, results chan<- result, a *App, progress func(domain.ProgressEvent)) {
	for j := range jobs {
		if progress != nil {
			// Emit the querying transition here so the spinner starts the moment a
			// worker picks the job up, before the (potentially slow) network call.
			progress(domain.ProgressEvent{Package: j.pkg.Name, Registry: j.reg.Name(), Phase: domain.PhaseQuerying})
		}
		entry, err := a.scanOne(ctx, j, progress)
		if err != nil {
			results <- result{err: err, reg: j.reg.Name(), pkg: j.pkg.Name}
			continue
		}
		results <- result{entry: entry, reg: j.reg.Name(), pkg: j.pkg.Name}
	}
}

// scanOne performs the core per-package analysis: query the registry, detect any
// collision, analyze signals, and compute the observation status from history.
// progress, when non-nil, receives the analyzing transition once the registry has
// responded (the network part is already covered by the querying event).
func (a *App) scanOne(ctx context.Context, j job, progress func(domain.ProgressEvent)) (*domain.ScanEntry, error) {
	now := time.Now()
	emit := func(e domain.ProgressEvent) {
		if progress != nil {
			progress(e)
		}
	}
	safe := func() *domain.ScanEntry {
		return &domain.ScanEntry{
			PackageName: j.pkg.Name,
			Ecosystem:   j.pkg.Ecosystem,
			Registry:    j.reg.Name(),
			Status:      domain.StatusSafe,
			Risk:        domain.RiskInfo,
			FirstSeen:   now,
			LastSeen:    now,
		}
	}

	info, err := j.reg.Query(ctx, j.pkg.Name)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return safe(), nil
	}

	// Registry responded with a public package; we now run the (local, fast)
	// collision + signal analysis. Surface that as a separate phase so the UI can
	// show "analyzing signals" rather than a static spinner.
	emit(domain.ProgressEvent{Package: j.pkg.Name, Registry: j.reg.Name(), Phase: domain.PhaseAnalyzing})

	collision, ok := domain.DetectCollision(j.pkg, info)
	if !ok {
		return safe(), nil
	}

	prev, err := a.store.Latest(j.pkg.Name, string(j.reg.Name()))
	if err != nil {
		return nil, err
	}

	assessment := domain.Analyze(collision, prev, now, a.cfg.Organization)

	status := domain.StatusNew
	firstSeen := now
	if prev != nil {
		firstSeen = prev.FirstSeen
		if prev.Risk != assessment.Risk {
			status = domain.StatusChanged
		} else {
			status = domain.StatusKnown
		}
	}

	return &domain.ScanEntry{
		PackageName: j.pkg.Name,
		Ecosystem:   j.pkg.Ecosystem,
		Registry:    j.reg.Name(),
		Collision:   collision,
		Signals:     assessment.Signals,
		Risk:        assessment.Risk,
		Threat:      assessment.Threat,
		Status:      status,
		FirstSeen:   firstSeen,
		LastSeen:    now,
		Version:     info.Version,
		Publisher:   info.Publisher,
		Downloads:   info.Downloads,
	}, nil
}
