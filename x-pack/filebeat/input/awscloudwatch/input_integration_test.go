// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// See _meta/terraform/README.md for integration test usage instructions.

//go:build integration && aws

package awscloudwatch

import (
	"context"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/stretchr/testify/assert"

	v2 "github.com/elastic/beats/v7/filebeat/input/v2"
	pubtest "github.com/elastic/beats/v7/libbeat/publisher/testing"
	"github.com/elastic/beats/v7/x-pack/filebeat/input/awscloudwatch/testutil"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	inputID = "test_id"
	message1 = "test1"
	message2 = "test2"
)

func newV2Context() (v2.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	return v2.Context{
		Logger:      logp.NewLogger(inputName).With("id", inputID),
		ID:          inputID,
		Cancelation: ctx,
	}, cancel
}

func createInput(t *testing.T, cfg *conf.C) *cloudwatchInput {
	inputV2, err := Plugin(logp.NewLogger(inputName), createTestInputStore()).Manager.Create(cfg)
	if err != nil {
		t.Fatal(err)
	}

	return inputV2.(*cloudwatchInput)
}

func makeTestConfigWithLogGroupNamePrefix(regionName string) *conf.C {
	return conf.MustNewConfigFrom(fmt.Sprintf(`---
log_group_name_prefix: %s
region_name: %s
`, testutil.LogGroupNamePrefix, regionName))
}

func TestInputWithLogGroupNamePrefix(t *testing.T) {
	logp.TestingSetup()

	tfConfig := testutil.GetTerraformOutputs(t)
	svc := testutil.NewCloudWatchLogsClient(t, tfConfig.AWSRegion)

	testutil.UploadLogMessage(t, svc, message1, tfConfig.LogGroup1, tfConfig.LogStream1)
	testutil.UploadLogMessage(t, svc, message2, tfConfig.LogGroup2, tfConfig.LogStream2)

	// sleep for 30 seconds to wait for the log messages to show up
	time.Sleep(30 * time.Second)

	cloudwatchInput := createInput(t, makeTestConfigWithLogGroupNamePrefix(tfConfig.AWSRegion))
	inputCtx, cancel := newV2Context()
	t.Cleanup(cancel)
	time.AfterFunc(30*time.Second, func() {
		cancel()
	})

	client := pubtest.NewChanClient(0)
	defer close(client.Channel)

	var errGroup errgroup.Group
	errGroup.Go(func() error {
		pipeline := pubtest.PublisherWithClient(client)
		return cloudwatchInput.Run(inputCtx, pipeline)
	})

	if err := errGroup.Wait(); err != nil {
		t.Fatal(err)
	}

	assert.EqualValues(t, cloudwatchInput.metrics.logEventsReceivedTotal.Get(), 2)
	assert.EqualValues(t, cloudwatchInput.metrics.logGroupsTotal.Get(), 2)
	assert.EqualValues(t, cloudwatchInput.metrics.cloudwatchEventsCreatedTotal.Get(), 2)
}
