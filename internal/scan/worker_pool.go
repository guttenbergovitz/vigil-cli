package scan

import (
	"context"
	"sync"

	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// ScanJob represents a single package to scan
type ScanJob struct {
	Node    *types.DependencyNode
	NodeKey string
}

// ScanResult represents scanning result for a package
type ScanResult struct {
	Node    *types.DependencyNode
	NodeKey string
	Vulns   []types.Vulnerability
	Error   error
}

// ScanFunc is the function signature for scanning a single package
type ScanFunc func(ctx context.Context, node *types.DependencyNode, nodeKey string) ([]types.Vulnerability, error)

// WorkerPool manages concurrent vulnerability scanning
type WorkerPool struct {
	numWorkers int
	jobChan    chan ScanJob
	resultChan chan ScanResult
	wg         sync.WaitGroup
	scanFunc   ScanFunc
	ctx        context.Context
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(ctx context.Context, numWorkers int, scanFunc ScanFunc) *WorkerPool {
	return &WorkerPool{
		numWorkers: numWorkers,
		jobChan:    make(chan ScanJob, numWorkers*2),
		resultChan: make(chan ScanResult, numWorkers*2),
		scanFunc:   scanFunc,
		ctx:        ctx,
	}
}

// Start initializes and starts worker goroutines
func (wp *WorkerPool) Start() {
	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
}

// worker processes jobs from the job channel
func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case job, ok := <-wp.jobChan:
			if !ok {
				return
			}

			vulns, err := wp.scanFunc(wp.ctx, job.Node, job.NodeKey)

			result := ScanResult{
				Node:    job.Node,
				NodeKey: job.NodeKey,
				Vulns:   vulns,
				Error:   err,
			}

			select {
			case wp.resultChan <- result:
			case <-wp.ctx.Done():
				return
			}
		}
	}
}

// Submit adds a job to the worker pool
func (wp *WorkerPool) Submit(job ScanJob) bool {
	select {
	case wp.jobChan <- job:
		return true
	case <-wp.ctx.Done():
		return false
	}
}

// Close waits for all workers to finish and closes channels
func (wp *WorkerPool) Close() {
	close(wp.jobChan)
	wp.wg.Wait()
	close(wp.resultChan)
}

// Results returns the result channel
func (wp *WorkerPool) Results() <-chan ScanResult {
	return wp.resultChan
}
