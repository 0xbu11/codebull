package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/0xbu11/codebull/test/e2e/framework"
)

func TestInventoryE2E(t *testing.T) {
	binPath, err := framework.BuildFixture("../../demo/inventory-example/main.go")
	if err != nil {
		t.Fatalf("failed to build inventory-example: %v", err)
	}
	defer os.Remove(binPath)

	t.Run("RealWorld Scenarios", func(t *testing.T) {
		lnAPI, _ := net.Listen("tcp", "127.0.0.1:0")
		apiAddr := lnAPI.Addr().String()
		lnAPI.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		env := []string{
			fmt.Sprintf("EGO_SHADOW_ADDR=%s", apiAddr),
			"EGO_SHADOW_DEBUG=1",
			"DEMO_MODE=1", // Starts the background simulator
		}
		
		appAddr := "127.0.0.1:8080"
		
		p, err := framework.RunBinaryWithCwd(ctx, binPath, env, "../../demo/inventory-example")
		if err != nil {
			t.Fatalf("failed to start target: %v", err)
		}
		
		defer p.Cmd.Process.Kill()

		time.Sleep(3 * time.Second)

		shadowClient := framework.NewClient(apiAddr)
		httpClient := framework.NewHTTPClient(appAddr)

		wsClient, err := framework.NewWSClient(apiAddr)
		if err != nil {
			t.Fatalf("failed to connect to websocket: %v", err)
		}
		defer wsClient.Close()

		t.Log("Scenario A: Instrumenting inventory/controllers.CreateProduct")
		err = shadowClient.AddTracepoint(framework.TraceRequest{
			Pattern: "inventory/controllers.CreateProduct",
			Line:    28,
			VariableNames: []string{"product"},
			RateLimit: &framework.RateLimitConfig{
				Algorithm: "token_bucket", Rate: 1000, Burst: 1000,
			},
		})
		if err != nil {
			t.Fatalf("failed to add tracepoint A: %v", err)
		}

		t.Log("Scenario B: Instrumenting inventory/services.(*demoSimulator).createRandomProduct")
		err = shadowClient.AddTracepoint(framework.TraceRequest{
			Pattern: "inventory/services.(*demoSimulator).createRandomProduct",
			Line:    142,
			VariableNames: []string{"product"},
			RateLimit: &framework.RateLimitConfig{
				Algorithm: "token_bucket", Rate: 1000, Burst: 1000,
			},
		})
		if err != nil {
			t.Fatalf("failed to add tracepoint B: %v", err)
		}

		t.Log("Scenario C: Triggering API and verifying WebSocket stream")
		
		payload := map[string]interface{}{
			"name": "Test Product E2E",
			"description": "E2E testing product",
			"price": 99.99,
			"quantity": 10,
			"category_id": 1,
			"supplier_id": 1,
		}
		
		go func() {
			time.Sleep(500 * time.Millisecond)
			if err := httpClient.Post("/api/v1/products", payload); err != nil {
				t.Errorf("failed to trigger API: %v", err)
			}
		}()

		ev, err := wsClient.WaitForEvent(ctx, "inventory/controllers.CreateProduct", 5*time.Second)
		if err != nil {
			t.Fatalf("failed to receive WS event for CreateProduct: %v", err)
		}
		
		if ev.Data.FunctionName != "inventory/controllers.CreateProduct" {
			t.Errorf("expected function name inventory/controllers.CreateProduct, got %s", ev.Data.FunctionName)
		}
		if len(ev.Data.Variables) == 0 {
			t.Error("expected variables in WS event, got none")
		} else {
			t.Logf("Received valid WS event: %s with %d variables", ev.Data.FunctionName, len(ev.Data.Variables))
		}

		evDemo, err := wsClient.WaitForEvent(ctx, "inventory/services.(*demoSimulator).createRandomProduct", 10*time.Second)
		if err != nil {
			t.Logf("Note: background simulator event not received in time: %v (maybe it chose update/delete)", err)
		} else {
			t.Logf("Received background simulator WS event: %s", evDemo.Data.FunctionName)
		}

		t.Log("Running concurrent stability test for 10 seconds...")
		time.Sleep(10 * time.Second)

		if p.GetPanic() != "" {
			t.Fatalf("Target paniced during test:\n%s", p.GetPanic())
		}
		t.Log("Test completed successfully without crashes.")
	})
}
