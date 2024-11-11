package webhook

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/trivy-web-dash/types"
)

func Do(url string, report types.Report) (*int, error) {
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(report)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, buf)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err

	}

	defer resp.Body.Close()
	return &resp.StatusCode, nil
}
