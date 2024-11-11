package redis

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/trivy-web-dash/pkg/db"
	"github.com/trivy-web-dash/pkg/job"
	"github.com/trivy-web-dash/pkg/logger"
	"github.com/trivy-web-dash/types"
	"golang.org/x/xerrors"
)

type store struct {
	pool *redis.Pool
	log  logger.Logger
}

func NewPool(redisurl string) (*redis.Pool, error) {
	var rp = &redis.Pool{
		MaxActive: 5,
		MaxIdle:   5,
		Wait:      true,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", redisurl, redis.DialDatabase(5))
		},
	}
	conn := rp.Get()
	defer conn.Close()
	_, err := conn.Do("PING")
	if err != nil {
		return nil, err
	}
	return rp, nil
}

func NewStore(rp *redis.Pool) db.Store {
	return &store{
		pool: rp,
	}
}

func (s *store) Create(scanJob job.ScanJob) error {
	conn := s.pool.Get()
	defer s.close(conn)

	bytes, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job: %w", err)
	}

	key := s.getKeyForScanJob(scanJob.ID)
	_, err = conn.Do("SET", key, string(bytes), "NX", "EX", int((1 * time.Hour).Seconds()))
	if err != nil {
		return xerrors.Errorf("creating scan job: %w", err)
	}

	return nil
}

func (s *store) update(scanJob job.ScanJob) error {
	conn := s.pool.Get()
	defer s.close(conn)

	scanJobBytes, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job: %w", err)
	}

	key := s.getKeyForScanJob(scanJob.ID)
	_, err = conn.Do("SET", key, string(scanJobBytes), "EX", int((1 * time.Hour).Seconds()))
	if err != nil {
		return xerrors.Errorf("creating scan job: %w", err)
	}

	return nil
}

func (s *store) Get(scanJobID string) (*job.ScanJob, error) {
	conn := s.pool.Get()
	defer s.close(conn)

	key := s.getKeyForScanJob(scanJobID)
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		if err == redis.ErrNil {
			return nil, nil
		}
		return nil, err
	}

	var scanJob job.ScanJob
	err = json.Unmarshal([]byte(value), &scanJob)
	if err != nil {
		return nil, err
	}
	return &scanJob, nil
}

func (s *store) GetAllJobStatus() ([]job.ScanJob, error) {
	conn := s.pool.Get()
	defer s.close(conn)

	values, err := (conn.Do("KEYS", "*scan-job*"))
	if err != nil {
		if err == redis.ErrNil {
			return nil, nil
		}
		return nil, err
	}

	var jobs []job.ScanJob
	for _, value := range values.([]interface{}) {
		valueBytes, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}

		unquotedValue, err := strconv.Unquote(string(valueBytes))
		if err != nil {
			return nil, err
		}

		decodedValue, err := base64.StdEncoding.DecodeString(unquotedValue)
		if err != nil {
			return nil, err
		}

		value, err := redis.String(conn.Do("GET", decodedValue))
		if err != nil {
			if err == redis.ErrNil {
				return nil, nil
			}
			return nil, err
		}

		scanJob := job.ScanJob{}
		err = json.Unmarshal([]byte(value), &scanJob)
		if err != nil {
			return nil, err
		}

		jobs = append(jobs, scanJob)
	}

	return jobs, nil
}

func (s *store) UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, errs ...string) error {
	scanJob, err := s.Get(scanJobID)
	if err != nil {
		return err
	}
	scanJob.Status = newStatus
	if len(errs) > 0 {
		scanJob.Error = errs[0]
	}

	return s.update(*scanJob)
}

func (s *store) UpdateReport(scanJobID string, report types.Report) error {
	scanJob, err := s.Get(scanJobID)
	if err != nil {
		return err
	}
	scanJob.Report = report
	return s.update(*scanJob)
}

func (s *store) getKeyForScanJob(scanJobID string) string {
	return fmt.Sprintf("%s:scan-job:%s", "trivy-scanner", scanJobID)
}

func (s *store) close(conn redis.Conn) {
	err := conn.Close()
	if err != nil {
		s.log.Error("Error while closing connection")
	}
}
