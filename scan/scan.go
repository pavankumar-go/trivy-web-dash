package scan

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

func GetScanStatus(trivyWebScannerStatusURL string) ([]byte, error) {
	return makeRequest("GET", trivyWebScannerStatusURL, nil)
}

func makeRequest(method, url string, reqBytes []byte) (responseBytes []byte, err error) {
	var httpClient = new(http.Client)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, errors.New("failed to create new http request: " + err.Error())
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.New("failed to send http request: " + err.Error())
	}

	responseBytes = make([]byte, resp.ContentLength)
	_, err = io.ReadFull(resp.Body, responseBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("unsucessful response: " + string(responseBytes))
	}

	return responseBytes, err
}
