package db

import (
	"github.com/trivy-web-dash/pkg/job"
	"github.com/trivy-web-dash/types"
)

type Store interface {
	Create(scanJob job.ScanJob) error
	Get(scanJobID string) (*job.ScanJob, error)
	GetAllJobStatus() ([]job.ScanJob, error)
	UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, error ...string) error
	UpdateReport(scanJobID string, report types.Report) error
}
