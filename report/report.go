package report

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"strings"
	"time"

	"github.com/trivy-web-dash/pkg/db"
	redisx "github.com/trivy-web-dash/pkg/db/redis"
	"github.com/trivy-web-dash/types"
)

type ReportClient struct {
	client db.Store
}

const expirationTime = 2000 * time.Hour

var reportClient *ReportClient

func NewReportClient(redisURI, redisPass string) error {
	pool, err := redisx.NewPool(redisURI, redisPass, "1")
	if err != nil {
		return err
	}

	reportClient = &ReportClient{client: redisx.NewStore(pool)}
	return nil
}

func GetReportClient() *ReportClient {
	return reportClient
}

func (c *ReportClient) Get(ctx context.Context, image string) (types.Report, time.Duration, error) {
	key := strings.TrimPrefix(image, "/")
	value, ttl, err := c.client.GetwithTTL(key)
	if err != nil {
		return types.Report{}, 0, err
	}

	var report *types.Report
	if err := json.Unmarshal(value, &report); err != nil {
		return types.Report{}, 0, err
	}

	return *report, ttl, nil
}

func (c *ReportClient) Set(ctx context.Context, report types.Report) error {
	var b bytes.Buffer
	target := report.Results[0].Target
	reg := strings.Split(target, " ")

	if err := gob.NewEncoder(&b).Encode(report); err != nil {
		return err
	}

	jbytes, err := json.Marshal(report)
	if err != nil {
		return err
	}

	if err := c.client.SetwithTTL(reg[0], jbytes, expirationTime); err != nil {
		return err
	}

	return nil
}
