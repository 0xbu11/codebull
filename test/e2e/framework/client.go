package framework

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type TraceRequest struct {
	Pattern           string   `json:"pattern"`
	Line              int      `json:"line"`
	VariableNames     []string `json:"variable_names"`
	CollectStacktrace bool     `json:"collect_stacktrace"`
	RateLimit         *RateLimitConfig `json:"rate_limit,omitempty"`
}

type RateLimitConfig struct {
	Algorithm string  `json:"algorithm"`
	Rate      float64 `json:"rate"`
	Burst     int     `json:"burst"`
}

type Client struct {
	BaseURL string
}

func NewClient(addr string) *Client {
	return &Client{BaseURL: "http://" + addr}
}

func (c *Client) AddTracepoint(req TraceRequest) error {
	wrapper := struct {
		Point TraceRequest `json:"point"`
	}{
		Point: req,
	}
	body, _ := json.Marshal(wrapper)
	url := fmt.Sprintf("%s/trace?pattern=%s&line=%d", c.BaseURL, req.Pattern, req.Line)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return fmt.Errorf("bad status: %d, body: %s", resp.StatusCode, buf.String())
	}
	return nil
}
