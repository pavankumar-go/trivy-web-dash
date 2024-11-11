package summary

import (
	"bytes"
	"context"
	"encoding/gob"
	"log"
	"os"
	"strings"
	"time"

	"github.com/trivy-web-dash/types"
	"github.com/trivy-web-dash/util"

	"github.com/go-redis/redis/v8"
)

type SummaryClient struct {
	client *redis.Client
}

var summaryClient *SummaryClient

const expirationTime = 2000 * time.Hour

func NewSummaryClient() error {
	sc := redis.NewClient(&redis.Options{
		Addr:        os.Getenv("REDIS"),
		DB:          0,
		DialTimeout: 100 * time.Millisecond,
		ReadTimeout: 100 * time.Millisecond,
	})

	summaryClient = &SummaryClient{client: sc}
	if _, err := summaryClient.client.Ping(context.Background()).Result(); err != nil {
		return err
	}
	return nil
}

func GetSummaryClient() *SummaryClient {
	if summaryClient.client == nil {
		if err := NewSummaryClient(); err != nil {
			log.Fatalln("Failed to initialize summary client: ", err)
		}
		return summaryClient
	}
	return summaryClient
}

func (c *SummaryClient) GetAll(ctx context.Context) ([]types.Summary, error) {
	var result []types.Summary
	iter := c.client.Scan(ctx, 0, "*", 0).Iterator()
	for iter.Next(ctx) {
		ttl := c.client.TTL(ctx, iter.Val())
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
			LastScan: util.ConvertToHumanReadable(expirationTime - ttl.Val()),
		}
		result = append(result, r)
	}

	if err := iter.Err(); err != nil {
		log.Println("error during iteration: ", err)
		return nil, err
	}

	return result, nil
}

func (c *SummaryClient) Get(ctx context.Context, key string) (map[string]int, error) {
	cc := c.client.Get(ctx, key)

	cb, err := cc.Bytes()
	if err != nil {
		return nil, err
	}

	b := bytes.NewReader(cb)
	var value map[string]int
	if err := gob.NewDecoder(b).Decode(&value); err != nil {
		return nil, err
	}

	return value, nil
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
		return err
	}

	return c.client.Set(ctx, reg[0], b.Bytes(), expirationTime).Err()
}
