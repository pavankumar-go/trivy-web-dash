package queue

import (
	"fmt"
	"log"

	"github.com/gocraft/work"
	"github.com/gomodule/redigo/redis"
	"github.com/trivy-web-dash/pkg/db"
	"github.com/trivy-web-dash/pkg/job"
)

const (
	scanArtifactJobName = "scan_artifact"
	scanRequestJobArg   = "scan_request"
)

type Enqueuer interface {
	Enqueue(image string) (job.ScanJob, error)
}

type enqueuer struct {
	enqueuer *work.Enqueuer
	store    db.Store
}

func NewEnqueuer(redisPool *redis.Pool, store db.Store) Enqueuer {
	return &enqueuer{
		enqueuer: work.NewEnqueuer("trivy-scanner", redisPool),
		store:    store,
	}
}

func (e *enqueuer) Enqueue(image string) (job.ScanJob, error) {
	log.Println("Enqueueing scan job")
	j, err := e.enqueuer.Enqueue(scanArtifactJobName, work.Q{
		scanRequestJobArg: string(image),
	})

	if err != nil {
		return job.ScanJob{}, fmt.Errorf("enqueuing scan artifact job: %v", err)
	}

	log.Println("Successfully enqueued scan job")
	scanJob := job.ScanJob{
		ID:      j.ID,
		Status:  job.Queued,
	}

	err = e.store.Create(scanJob)
	if err != nil {
		return job.ScanJob{}, fmt.Errorf("creating scan job %v", err)
	}

	return scanJob, nil
}
