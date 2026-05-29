// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package outputs

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"

	"github.com/elastic/beats/v7/libbeat/publisher"
	"github.com/elastic/elastic-agent-libs/testing"
)

var _ FailoverClient = (*failoverClient)(nil)

type failoverClient struct {
	clients   []NetworkClient
	active    int
	connected bool
	mu        sync.RWMutex
}

var (
	// ErrNoConnectionConfigured indicates no configured connections for publishing.
	ErrNoConnectionConfigured = errors.New("No connection configured")

	errNoActiveConnection = errors.New("No active connection")
)

// NewFailoverClient combines a set of NetworkClients into one FailoverClient,
// with at most one active client. If the active client fails, another client
// will be used.
func NewFailoverClient(clients []NetworkClient) NetworkClient {
	if len(clients) == 1 {
		return clients[0]
	}

	return &failoverClient{
		clients: clients,
		active:  -1,
	}
}

func (f *failoverClient) NumOfClients() int {
	return len(f.clients)
}

func (f *failoverClient) IsConnected(_ context.Context) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.connected
}

func (f *failoverClient) Connect(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var (
		next   int
		active = f.active
		l      = len(f.clients)
	)

	switch {
	case l == 0:
		f.connected = false
		return ErrNoConnectionConfigured
	case l == 1:
		next = 0
	case l == 2 && 0 <= active && active <= 1:
		next = 1 - active
	default:
		for {
			// Connect to random server to potentially spread the
			// load when large number of beats with same set of sinks
			// are started up at about the same time.
			next = rand.Int() % l
			if next != active {
				break
			}
		}
	}

	client := f.clients[next]
	f.active = next
	if err := client.Connect(ctx); err != nil {
		f.connected = false
		return err
	}
	f.connected = true
	return nil
}

func (f *failoverClient) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.active < 0 {
		return errNoActiveConnection
	}
	err := f.clients[f.active].Close()
	f.connected = false
	return err
}

func (f *failoverClient) Publish(ctx context.Context, batch publisher.Batch) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.active < 0 || !f.connected {
		batch.Retry()
		return errNoActiveConnection
	}

	err := f.clients[f.active].Publish(ctx, batch)
	if err != nil {
		f.connected = false
	}
	return err
}

func (f *failoverClient) Test(d testing.Driver) {
	for i, client := range f.clients {
		c, ok := client.(testing.Testable)
		d.Run(fmt.Sprintf("Client %d", i), func(d testing.Driver) {
			if !ok {
				d.Fatal("output", errors.New("client doesn't support testing"))
			}
			c.Test(d)
		})
	}
}

func (f *failoverClient) String() string {
	names := make([]string, len(f.clients))

	for i, client := range f.clients {
		names[i] = client.String()
	}

	return "failover(" + strings.Join(names, ",") + ")"
}
