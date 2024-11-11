package queue

import (
	"github.com/gocraft/work"
	"github.com/gomodule/redigo/redis"
	"github.com/trivy-web-dash/pkg/logger"
	scanner "github.com/trivy-web-dash/pkg/trivy/controller"
)

const (
	scanJobDefaultPriority = 1 // The highest
	scanJobMaxFailures     = 1
)

type Worker interface {
	Start()
	Stop()
}

type worker struct {
	workerPool *work.WorkerPool
	log        logger.Logger
}

func NewWorker(redisPool *redis.Pool, controller scanner.Controller, l logger.Logger) Worker {
	workerPool := work.NewWorkerPool(workerContext{}, uint(5), "trivy-scanner", redisPool)

	// Note: For each scan job a new instance of the workerContext struct is created.
	// Therefore, the only way to do a proper dependency injection is to use such closure
	// and the following middleware as the first step in the processing chain.
	workerPool.Middleware(func(ctx *workerContext, job *work.Job, next work.NextMiddlewareFunc) error {
		ctx.controller = controller
		return next()
	})

	workerPool.JobWithOptions(scanArtifactJobName,
		work.JobOptions{
			Priority: scanJobDefaultPriority,
			MaxFails: scanJobMaxFailures,
		}, (*workerContext).ScanArtifact)

	return &worker{
		workerPool: workerPool,
		log:        l,
	}
}

func (w *worker) Start() {
	w.log.Info("starting worker")
	w.workerPool.Start()
}

func (w *worker) Stop() {
	w.log.Info("stopping worker")
	w.workerPool.Stop()
	w.log.Info("stopped worker")
}

// workerContext is a context for running scan jobs.
type workerContext struct {
	controller scanner.Controller
}

func (s *workerContext) ScanArtifact(job *work.Job) (err error) {
	// "scan_request"
	return s.controller.Scan(job.ID, job.ArgString(scanRequestJobArg))
}
