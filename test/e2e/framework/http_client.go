package framework

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type HTTPClient struct {
	BaseURL string
}

func NewHTTPClient(addr string) *HTTPClient {
	return &HTTPClient{BaseURL: "http://" + addr}
}

func (c *HTTPClient) Post(path string, payload interface{}) error {
	body, _ := json.Marshal(payload)
	resp, err := http.Post(c.BaseURL+path, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return fmt.Errorf("unexpected status: %s, body: %s", resp.Status, buf.String())
	}
	return nil
}

func (c *HTTPClient) Get(path string) error {
	resp, err := http.Get(c.BaseURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}
	return nil
}
