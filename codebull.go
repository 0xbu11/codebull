//go:build !go1.23

package codebull

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"sync"

	"github.com/0xbu11/codebull/pkg/debugflag"
	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/instrument"
	"github.com/0xbu11/codebull/pkg/server"
	"github.com/0xbu11/codebull/pkg/trap"
)

var (
	DefaultManager *instrument.Manager
	startMu        sync.Mutex
	currentServer  *http.Server
	currentDone    chan error
	currentAddr    string
	currentIsAuto  bool
)

const (
	defaultListenAddr = ":8888"
	envShadowAddr     = "EGO_SHADOW_ADDR"
	envShadowPort     = "EGO_SHADOW_PORT"
)

func resolveListenAddr() string {
	if addr := strings.TrimSpace(os.Getenv(envShadowAddr)); addr != "" {
		return addr
	}

	if port := strings.TrimSpace(os.Getenv(envShadowPort)); port != "" {
		port = strings.TrimPrefix(port, ":")
		portNum, err := strconv.Atoi(port)
		if err == nil && portNum > 0 && portNum <= 65535 {
			return ":" + port
		}
		debugflag.Printf("Invalid %s=%q, fallback to %s", envShadowPort, port, defaultListenAddr)
	}

	return defaultListenAddr
}

func init() {
	go func() {
		if err := Start(resolveListenAddr()); err != nil {
			debugflag.Printf("Shadow server failed to start: %v", err)
		}
	}()
}

func ensureManagerAndMux() (*http.ServeMux, error) {
	var err error
	if DefaultManager == nil {
		DefaultManager, err = instrument.NewManager()
		if err != nil {
			if DefaultManager == nil {
				return nil, fmt.Errorf("failed to create manager: %w", err)
			}
			debugflag.Printf("Warning: DWARF init failed: %v", err)
		}
	}

	callbackAddr := uint64(reflect.ValueOf(trap.Handler).Pointer())
	DefaultManager.SetCollectorAddr(callbackAddr)

	srv := server.NewServer(DefaultManager)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", srv.HandleWebSocket)
	mux.HandleFunc("/health", srv.HandleHealth)
	mux.HandleFunc("/trace", srv.HandleTrace)
	mux.HandleFunc("/trace/status", srv.HandleTraceStatus)

	return mux, nil
}

func RegisterFunction(fn *function.Function) error {
	if DefaultManager == nil {
		var err error
		DefaultManager, err = instrument.NewManager()
		if DefaultManager == nil {
			return fmt.Errorf("failed to initialize manager: %v", err)
		}
	}
	return DefaultManager.RegisterFunction(fn)
}

func Start(addr string) error {
	requestedAddr := strings.TrimSpace(addr)
	isExplicit := requestedAddr != ""
	if !isExplicit {
		requestedAddr = resolveListenAddr()
	}

	for {
		startMu.Lock()
		runningServer := currentServer
		runningDone := currentDone
		runningAddr := currentAddr
		runningIsAuto := currentIsAuto

		if runningServer == nil {
			mux, err := ensureManagerAndMux()
			if err != nil {
				startMu.Unlock()
				return err
			}

			ln, err := net.Listen("tcp", requestedAddr)
			if err != nil {
				startMu.Unlock()
				return err
			}

			httpSrv := &http.Server{Handler: mux}
			done := make(chan error, 1)

			currentServer = httpSrv
			currentDone = done
			currentAddr = requestedAddr
			currentIsAuto = !isExplicit

			debugflag.Println("Shadow: Routes registered: /ws, /health, /trace, /trace/status")
			debugflag.Printf("Shadow: listening on %s", requestedAddr)
			startMu.Unlock()

			go func(server *http.Server, listener net.Listener, doneCh chan error) {
				err := server.Serve(listener)
				if err == http.ErrServerClosed {
					err = nil
				}

				startMu.Lock()
				if currentServer == server {
					currentServer = nil
					currentDone = nil
					currentAddr = ""
					currentIsAuto = false
				}
				startMu.Unlock()

				doneCh <- err
				close(doneCh)
			}(httpSrv, ln, done)

			return <-done
		}

		if runningAddr == requestedAddr {
			startMu.Unlock()
			return nil
		}

		if isExplicit && runningIsAuto {
			startMu.Unlock()
			_ = runningServer.Close()
			if runningDone != nil {
				<-runningDone
			}
			continue
		}

		startMu.Unlock()
		if isExplicit {
			return fmt.Errorf("shadow server already listening on %s", runningAddr)
		}
		return nil
	}
}
