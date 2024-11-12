package scanner

import (
	"context"
	"log"

	"github.com/trivy-web-dash/pkg/db"
	"github.com/trivy-web-dash/pkg/job"
	"github.com/trivy-web-dash/pkg/logger"
	tc "github.com/trivy-web-dash/pkg/trivy"
	"github.com/trivy-web-dash/report"
	"github.com/trivy-web-dash/summary"
	"golang.org/x/xerrors"
)

type Controller interface {
	Scan(scanJobID string, image string) error
}

type controller struct {
	store       db.Store
	trivyClient *tc.TC
	log         logger.Logger
}

func NewController(store db.Store, tc *tc.TC, l logger.Logger) Controller {
	return &controller{
		store:       store,
		trivyClient: tc,
		log:         l,
	}
}

func (c *controller) Scan(scanJobID string, image string) error {
	ctx := context.Background()
	c.log.Infof("starting scan : %s", scanJobID)
	err := c.scan(ctx, scanJobID, image)
	if err != nil {
		err = c.store.UpdateStatus(scanJobID, job.ScanFail, err.Error())
		if err != nil {
			return xerrors.Errorf("updating scan job as failed: %v", err)
		}
	}
	return nil
}

func (c *controller) scan(ctx context.Context, scanJobID string, image string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	scanReport, err := c.trivyClient.Scan(image)
	if err != nil {
		c.store.UpdateStatus(scanJobID, job.ScanFail)
		return xerrors.Errorf("running trivy wrapper: %v", err)
	}

	c.log.Infof("job : %s  - status :%s. Updating vulnerability report in db...", scanJobID, job.Scanned)

	err = c.store.UpdateReport(scanJobID, *scanReport)
	if err != nil {
		c.log.Errorf("Error UpdateReport: %v", err)
		return xerrors.Errorf("saving scan report: %v", err)
	}

	if err := c.store.UpdateStatus(scanJobID, job.Scanned); err != nil {
		return err
	}
	c.log.Info("report updated")

	_, err = c.store.Get(scanJobID)
	if err != nil {
		return err
	}

	err = report.GetReportClient().Set(ctx, *scanReport)
	if err != nil {
		log.Fatalf("GetReportClient REPORT SET %v", err)
	}

	err = summary.GetSummaryClient().Set(ctx, *scanReport)
	if err != nil {
		log.Fatalf("GetSummaryClient REDIS SET %v", err)
	}

	err = c.store.UpdateStatus(scanJobID, job.Done)
	if err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	return nil
}
