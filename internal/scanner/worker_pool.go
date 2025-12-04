package scanner

import (
	"sync"

	"github.com/guttenbergovitz/vigil-cli/internal/osv"
	"github.com/guttenbergovitz/vigil-cli/pkg/models"
)

// WorkerPool manages concurrent vulnerability scanning
type WorkerPool struct {
	numWorkers int
	jobChan    chan ScanJob
	resultChan chan ScanResult
	wg         sync.WaitGroup
	osvClient  *osv.Client
}

// ScanJob represents a single package to scan
type ScanJob struct {
	Node *models.DependencyNode
}

// ScanResult represents scanning result for a package
type ScanResult struct {
	Node         *models.DependencyNode
	Vulnerabilities []models.Vulnerability
	Error        error
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(numWorkers int, osvClient *osv.Client) *WorkerPool {
	return &WorkerPool{
		numWorkers: numWorkers,
		jobChan:    make(chan ScanJob, numWorkers*2),
		resultChan: make(chan ScanResult, numWorkers*2),
		osvClient:  osvClient,
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

	for job := range wp.jobChan {
		vulns, err := wp.osvClient.Query(job.Node.Name, job.Node.Version)

		result := ScanResult{
			Node:            job.Node,
			Vulnerabilities: vulns,
			Error:           err,
		}

		wp.resultChan <- result
	}
}

// Submit adds a job to the worker pool
func (wp *WorkerPool) Submit(job ScanJob) {
	wp.jobChan <- job
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
