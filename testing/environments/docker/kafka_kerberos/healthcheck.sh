#!/bin/bash
# Licensed to Elasticsearch under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

set -e

export KRB5_CONFIG=/etc/krb5.conf
AD_KDC_HOST=${AD_KDC_HOST:-35.232.29.86}
REALM_NAME=${REALM_NAME:-INGEST.EXAMPLE.COM}
KAFKA_KEYTAB=${KAFKA_KEYTAB:-/etc/kafka_localhost.keytab}
KAFKA_SERVICE_HOST=${KAFKA_SERVICE_HOST:-localhost}
BEATS_USER=${BEATS_USER:-beats}
BEATS_PASSWORD=${BEATS_PASSWORD:-Testing1!}

# Broker keytab must work against AD.
kinit -k -t "${KAFKA_KEYTAB}" "kafka/${KAFKA_SERVICE_HOST}@${REALM_NAME}"
kdestroy || true

# Client principal (AD user) must work.
printf '%s\n' "${BEATS_PASSWORD}" | kinit "${BEATS_USER}@${REALM_NAME}"
klist
kdestroy || true

# PLAINTEXT inside listener responds.
TOPIC="kerb-health-$(date '+%s-%N')"
${KAFKA_HOME}/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --create --partitions 1 --topic "${TOPIC}" --replication-factor 1
${KAFKA_HOME}/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --delete --topic "${TOPIC}"

exit 0
