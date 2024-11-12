package db

import (
	"time"

	"github.com/trivy-web-dash/pkg/job"
	"github.com/trivy-web-dash/types"
)

type Store interface {
	Create(scanJob job.ScanJob) error
	Get(scanJobID string) (*job.ScanJob, error)
	GetAllJobStatus() ([]job.ScanJob, error)
	UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, error ...string) error
	UpdateReport(scanJobID string, report types.Report) error
	SetwithTTL(key string, value []byte, ttl time.Duration) error
	GetwithTTL(key string) ([]byte, time.Duration, error)
	GetAllKeys() ([]string, error)
}
