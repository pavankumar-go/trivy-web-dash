package summary

import (
	"bytes"
	"context"
	"encoding/gob"
	"strings"
	"time"

	"github.com/trivy-web-dash/pkg/db"
	redisx "github.com/trivy-web-dash/pkg/db/redis"
	"github.com/trivy-web-dash/pkg/logger"
	"github.com/trivy-web-dash/types"
	"github.com/trivy-web-dash/util"
)

type SummaryClient struct {
	client db.Store
	log    logger.Logger
}

var summaryClient *SummaryClient

const expirationTime = 2000 * time.Hour

func NewSummaryClient(redisURI, redisPass string, redisTLS, redisTLSSkipVerify bool, log logger.Logger) error {
	pool, err := redisx.NewPool(redisURI, redisPass, "2", redisTLS, redisTLSSkipVerify)
	if err != nil {
		return err
	}

	summaryClient = &SummaryClient{client: redisx.NewStore(pool), log: log}
	return nil
}

func GetReportClient() *SummaryClient {
	return summaryClient
}

func GetSummaryClient() *SummaryClient {
	return summaryClient
}

func (c *SummaryClient) GetAll(ctx context.Context) ([]types.Summary, error) {
	var result []types.Summary
	keys, err := c.client.GetAllKeys("vulndb*")
	if err != nil {
		c.log.Error(err)
		return nil, err
	}

	if len(keys) != 0 {
		for _, key := range keys {
			keyBytes, ttl, err := c.client.GetwithTTL(key)
			if err != nil {
				c.log.Error(err)
				return nil, err
			}

			b := bytes.NewReader(keyBytes)
			var s map[string]int
			if err := gob.NewDecoder(b).Decode(&s); err != nil {
				c.log.Error(err)
				return nil, err
			}

			r := types.Summary{
				Image:    key,
				VSummary: s,
				LastScan: util.ConvertToHumanReadable(expirationTime - ttl),
			}
			result = append(result, r)
		}
	}

	return result, nil
}

func (c *SummaryClient) Get(ctx context.Context, key string) (map[string]int, error) {
	value, _, err := c.client.GetwithTTL(key)
	if err != nil {
		c.log.Error(err)
		return nil, err
	}
	b := bytes.NewReader(value)
	var summary map[string]int
	if err := gob.NewDecoder(b).Decode(&value); err != nil {
		c.log.Error(err)
		return nil, err
	}

	return summary, nil
}

func (c *SummaryClient) Set(ctx context.Context, report types.Report) error {
	var b bytes.Buffer
	var summary = map[string]int{}
	target := report.Results[0].Target
	reg := strings.Split(target, " ")

	for _, t := range report.Results {
		for _, v := range t.Vulnerabilities {
			_, ok := summary[v.Severity]
			if !ok {
				summary[v.Severity] = 1
			} else {
				summary[v.Severity]++
			}
		}
	}
	if err := gob.NewEncoder(&b).Encode(summary); err != nil {
		c.log.Error(err)
		return err
	}

	if err := c.client.SetwithTTL(reg[0], b.Bytes(), expirationTime); err != nil {
		c.log.Error(err)
		return err
	}
	return nil
}
