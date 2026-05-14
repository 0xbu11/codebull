package framework

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

type WSEvent struct {
	Type string    `json:"type"`
	Data EventData `json:"data"`
}

type EventData struct {
	FunctionName string `json:"function_name"`
	Line         int    `json:"line"`
	Variables    []any  `json:"variables"`
	StackTrace   []any  `json:"stacktrace,omitempty"`
}

type WSClient struct {
	conn *websocket.Conn
}

func NewWSClient(addr string) (*WSClient, error) {
	u := url.URL{Scheme: "ws", Host: addr, Path: "/ws"}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}
	return &WSClient{conn: conn}, nil
}

func (c *WSClient) WaitForEvent(ctx context.Context, functionName string, timeout time.Duration) (*WSEvent, error) {
	resultChan := make(chan *WSEvent, 1)
	errChan := make(chan error, 1)

	go func() {
		c.conn.SetReadDeadline(time.Now().Add(timeout))
		for {
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Still waiting
				}
				errChan <- fmt.Errorf("read error: %w", err)
				return
			}

			var event WSEvent
			if err := json.Unmarshal(message, &event); err != nil {
				continue // Skip malformed messages
			}

			if event.Type == "report" {
				if functionName == "" || event.Data.FunctionName == functionName {
					resultChan <- &event
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errChan:
		return nil, err
	case ev := <-resultChan:
		return ev, nil
	}
}

func (c *WSClient) Close() error {
	return c.conn.Close()
}
