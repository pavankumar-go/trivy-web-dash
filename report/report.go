package report

import (
	"bytes"
	"context"
	"encoding/gob"
	"log"
	"os"
	"strings"
	"time"

	"github.com/trivy-web-dash/types"

	"github.com/go-redis/redis/v8"
)

type ReportClient struct {
	client *redis.Client
}

var reportClient *ReportClient

func NewReportClient() error {
	rc := redis.NewClient(&redis.Options{
		Addr:        os.Getenv("REDIS"),
		DB:          1,
		DialTimeout: 100 * time.Millisecond,
		ReadTimeout: 100 * time.Millisecond,
	})

	reportClient = &ReportClient{client: rc}
	if _, err := reportClient.client.Ping(context.Background()).Result(); err != nil {
		return err
	}
	return nil
}

func GetReportClient() *ReportClient {
	if reportClient.client == nil {
		if err := NewReportClient(); err != nil {
			log.Fatalln("Failed to initialize report client: ", err)
		}
		return reportClient
	}
	return reportClient
}

/*
func (c *SummaryClient) GetAll(ctx context.Context) ([]types.Summary, error) {
	var result []types.Summary
	iter := c.client.Scan(ctx, 0, "*", 0).Iterator()
	for iter.Next(ctx) {
		c := c.client.Get(ctx, iter.Val())
		cb, err := c.Bytes()
		if err != nil {
			return result, err
		}
		b := bytes.NewReader(cb)
		var s map[string]int
		if err := gob.NewDecoder(b).Decode(&s); err != nil {
			return result, err
		}
		r := types.Summary{
			Image:    iter.Val(),
			VSummary: s,
		}
		result = append(result, r)
	}
	if err := iter.Err(); err != nil {
		fmt.Println("boo")
	}
	fmt.Println(result)
	return result, nil
}
*/

func (c *ReportClient) Get(ctx context.Context, image string) (types.Report, *time.Duration, error) {
	q := strings.TrimPrefix(image, "/")
	cmd := c.client.Get(ctx, q)
	ttl := c.client.TTL(ctx, q)
	cmdb, err := cmd.Bytes()
	if err != nil {
		return types.Report{}, nil, err
	}

	b := bytes.NewReader(cmdb)

	var report types.Report

	if err := gob.NewDecoder(b).Decode(&report); err != nil {
		return types.Report{}, nil, err
	}
	expireAt := ttl.Val()
	return report, &expireAt, nil
}

func (c *ReportClient) Set(ctx context.Context, report types.Report) error {
	var b bytes.Buffer
	// fmt.Println(report)
	target := report.Results[0].Target
	reg := strings.Split(target, " ")

	if err := gob.NewEncoder(&b).Encode(report); err != nil {
		return err
	}

	return c.client.Set(ctx, reg[0], b.Bytes(), 2000*time.Hour).Err()
}
