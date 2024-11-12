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

func NewPool(redisurl, redisPass, redisDB string, redisTLS, redisTLSkipVerify bool) (*redis.Pool, error) {
	var rp = &redis.Pool{
		MaxActive: 5,
		MaxIdle:   5,
		Wait:      true,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", redisurl, redis.DialUseTLS(redisTLS), redis.DialTLSSkipVerify(redisTLSkipVerify))
			if err != nil {
				return nil, err
			}
			if redisPass != "" {
				if _, err := c.Do("AUTH", redisPass); err != nil {
					c.Close()
					return nil, err
				}
			}
			if _, err := c.Do("SELECT", redisDB); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
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
		return xerrors.Errorf("error scan job: %w", err)
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
		return xerrors.Errorf("error scan job: %w", err)
	}

	return nil
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

func (s *store) SetwithTTL(key string, value []byte, ttl time.Duration) error {
	conn := s.pool.Get()
	defer s.close(conn)

	_, err := conn.Do("SET", "vulndb/"+key, value, "EX", int(ttl.Seconds()))
	if err != nil {
		return xerrors.Errorf("error perform redis set: %w", err)
	}

	return nil
}

func (s *store) GetwithTTL(key string) ([]byte, time.Duration, error) {
	conn := s.pool.Get()
	defer s.close(conn)
	value, err := redis.Bytes(conn.Do("GET", key))
	if err != nil {
		return nil, 0, xerrors.Errorf("error perform redis get: %w", err)
	}

	ttl, err := redis.Int64(conn.Do("TTL", key))
	if err != nil {
		return nil, 0, xerrors.Errorf("error perform redis ttl: %w", err)
	}

	return value, time.Duration(ttl) * time.Second, nil
}

func (s *store) GetAllKeys(pattern string) ([]string, error) {
	conn := s.pool.Get()
	defer s.close(conn)

	value, err := redis.Strings(conn.Do("KEYS", pattern))
	if err != nil {
		return nil, xerrors.Errorf("error perform redis get all: %v", err)
	}
	return value, nil
}
