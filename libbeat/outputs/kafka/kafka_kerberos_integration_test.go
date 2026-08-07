// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration && !requirefips

package kafka

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/sarama"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/outputs/outest"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	kafkaKerberosHost        = "localhost:9095"
	kafkaKerberosConfigPath  = "testdata/krb5.conf"
	kafkaKerberosRealm       = "INGEST.EXAMPLE.COM"
	kafkaKerberosUsername    = "beats"
	kafkaKerberosPassword    = "Testing1!"
	kafkaKerberosServiceName = "kafka"
)

// TestKafkaPublishKerberosAware publishes one event through the Kafka output
// using SASL/GSSAPI (Kerberos), analogous to
// TestClientPublishEventKerberosAware for the Elasticsearch output.
//
// Targets the kafka_kerberos service from libbeat/docker-compose.yml
// (GSSAPI on :9095) with Active Directory as the KDC
// (testdata/krb5.conf → [VM-IP] / INGEST.EXAMPLE.COM).
func TestKafkaPublishKerberosAware(t *testing.T) {
	id := strconv.Itoa(rand.Int())
	testTopic := fmt.Sprintf("test-libbeat-kerberos-%s", id)

	kerberosCfg := map[string]any{
		"auth_type":    "password",
		"config_path":  kafkaKerberosConfigPath,
		"realm":        kafkaKerberosRealm,
		"service_name": kafkaKerberosServiceName,
		"username":     kafkaKerberosUsername,
		"password":     kafkaKerberosPassword,
	}

	cfg := makeConfig(t, map[string]any{
		"hosts":    []string{kafkaKerberosHost},
		"topic":    testTopic,
		"timeout":  "30s",
		"kerberos": kerberosCfg,
	})

	logger := logptest.NewTestingLogger(t, "kafka-kerberos")
	grp, err := makeKafka(nil, beat.Info{Beat: "libbeat", IndexPrefix: "testbeat", Logger: logger}, outputs.NewNilObserver(), cfg)
	require.NoError(t, err, "makeKafka with kerberos config")

	output, ok := grp.Clients[0].(*client)
	require.True(t, ok, "grp.Clients[0] didn't contain a ptr to client")
	require.NoError(t, output.Connect(context.Background()), "Connect with Kerberos")
	t.Cleanup(func() { _ = output.Close() })

	msg := "kerberos-kafka-" + id
	batch := outest.NewBatch(beat.Event{
		Timestamp: time.Now(),
		Fields: mapstr.M{
			"host":    "test-host",
			"message": msg,
		},
	})

	var wg sync.WaitGroup
	wg.Add(1)
	batch.OnSignal = func(_ outest.BatchSignal) { wg.Done() }

	require.NoError(t, output.Publish(context.Background(), batch), "Publish with Kerberos")
	wg.Wait()
	requiretBatchesACKed(t, []*outest.Batch{batch})

	stored := testReadFromKafkaTopicKerberos(t, kafkaKerberosHost, testTopic, kerberosCfg, 1, 30*time.Second)
	require.Len(t, stored, 1, "expected one message on kerberos topic")
	assert.Equal(t, msg, validateJSON(t, stored[0].Value, []beat.Event{{
		Fields: mapstr.M{"message": msg},
	}}))
}

func testReadFromKafkaTopicKerberos(
	t *testing.T,
	host, topic string,
	kerberosCfg map[string]any,
	nMessages int,
	timeout time.Duration,
) []*sarama.ConsumerMessage {
	t.Helper()

	readCfg := makeConfig(t, map[string]any{
		"hosts":    []string{host},
		"topic":    topic,
		"timeout":  "30s",
		"kerberos": kerberosCfg,
	})
	kCfg, err := ReadConfig(readCfg)
	require.NoError(t, err, "ReadConfig for kerberos consumer")
	saramaCfg, err := newSaramaConfig(logptest.NewTestingLogger(t, "kafka-kerberos-consumer"), kCfg)
	require.NoError(t, err, "newSaramaConfig for kerberos consumer")
	saramaCfg.Consumer.Return.Errors = true

	consumer, err := sarama.NewConsumer([]string{host}, saramaCfg)
	require.NoError(t, err, "sarama NewConsumer with Kerberos")
	t.Cleanup(func() { _ = consumer.Close() })

	// Topic may be auto-created on first produce; wait for partitions.
	var partitions []int32
	require.EventuallyWithTf(t, func(ct *assert.CollectT) {
		var err error
		partitions, err = consumer.Partitions(topic)
		require.NoError(ct, err)
		require.NotEmpty(ct, partitions)
	}, timeout, 200*time.Millisecond, "waiting for kerberos topic partitions")

	done := make(chan struct{})
	msgs := make(chan *sarama.ConsumerMessage)
	for _, partition := range partitions {
		pc, err := consumer.ConsumePartition(topic, partition, sarama.OffsetOldest)
		require.NoError(t, err)
		t.Cleanup(func() { _ = pc.Close() })

		go func(pc sarama.PartitionConsumer) {
			for {
				select {
				case msg, ok := <-pc.Messages():
					if !ok {
						return
					}
					select {
					case msgs <- msg:
					case <-done:
						return
					}
				case <-done:
					return
				}
			}
		}(pc)
	}

	var messages []*sarama.ConsumerMessage
	timer := time.After(timeout)
readLoop:
	for len(messages) < nMessages {
		select {
		case msg := <-msgs:
			messages = append(messages, msg)
		case <-timer:
			break readLoop
		}
	}
	close(done)
	return messages
}
