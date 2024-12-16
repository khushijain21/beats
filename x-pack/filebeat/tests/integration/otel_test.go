// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/libbeat/tests/integration"
	"github.com/elastic/mock-es/pkg/api"
)

var eventsLogFileCfg = `
filebeat.inputs:
  - type: filestream
    id: filestream-input-id
    enabled: true
    paths:
      - %s
output:
  elasticsearch:
    hosts:
      - localhost:4242
    protocol: http
logging:
  level: debug
  event_data:
    files:
      name: filebeat-my-event-log  
`

func TestEventsLoggerESOutput(t *testing.T) {
	filebeat := integration.NewBeat(
		t,
		"filebeat-otel",
		"../../filebeat.test",
		"otel",
	)

	logFilePath := filepath.Join(filebeat.TempDir(), "log.log")
	filebeat.WriteConfigFile(fmt.Sprintf(eventsLogFileCfg, logFilePath))

	logFile, err := os.Create(logFilePath)
	if err != nil {
		t.Fatalf("could not create file '%s': %s", logFilePath, err)
	}

	_, _ = logFile.WriteString(`
	this is first test log
	this is second test log
	`)
	if err := logFile.Sync(); err != nil {
		t.Fatalf("could not sync log file '%s': %s", logFilePath, err)
	}
	if err := logFile.Close(); err != nil {
		t.Fatalf("could not close log file '%s': %s", logFilePath, err)
	}

	s, mr := startMockES(t, "localhost:4242")

	filebeat.Start()

	// 1. Wait for one _bulk call
	waitForEventToBePublished(t, mr)

	s.Close()
}

func startMockES(t *testing.T, addr string) (*http.Server, metrics.Registry) {
	uid := uuid.Must(uuid.NewV4())
	mr := metrics.NewRegistry()
	es := api.NewAPIHandler(uid, "foo2", mr, time.Now().Add(24*time.Hour), 0, 0, 0, 0, 0)

	s := http.Server{Addr: addr, Handler: es, ReadHeaderTimeout: time.Second}
	go func() {
		if err := s.ListenAndServe(); !errors.Is(http.ErrServerClosed, err) {
			t.Errorf("could not start mock-es server: %s", err)
		}
	}()

	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr) //nolint: noctx // It's just a test
		if err != nil {
			//nolint: errcheck // We're just draining the body, we can ignore the error
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return false
		}
		return true
	},
		time.Second, time.Millisecond, "mock-es server did not start on '%s'", addr)

	return &s, mr
}

// waitForEventToBePublished waits for at least one event published
// by inspecting the count for `bulk.create.total` in `mr`. Once
// the counter is > 1, waitForEventToBePublished returns. If that
// does not happen within 10min, then the test fails with a call to
// t.Fatal.
func waitForEventToBePublished(t *testing.T, mr metrics.Registry) {
	t.Helper()
	require.Eventually(t, func() bool {
		total := mr.Get("bulk.create.total")

		if total == nil {
			return false
		}

		sc, ok := total.(*metrics.StandardCounter)
		if !ok {
			t.Fatalf("expecting 'bulk.create.total' to be *metrics.StandardCounter, but got '%T' instead",
				total,
			)
		}

		return sc.Count() > 1
	},
		30*time.Second, 100*time.Millisecond,
		"at least one bulk request must be made")
}
