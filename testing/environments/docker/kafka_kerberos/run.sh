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

wait_for_port() {
    count=40
    port=$1
    host=${2:-localhost}
    while ! nc -z "$host" "$port" && [[ $count -ne 0 ]]; do
        count=$((count - 1))
        [[ $count -eq 0 ]] && return 1
        sleep 0.5
    done
    nc -z "$host" "$port"
}

# Active Directory is the KDC (no in-container MIT krb5kdc).
AD_KDC_HOST=${AD_KDC_HOST:-35.232.29.86}
AD_DOMAIN=${AD_DOMAIN:-ingest.example.com}
REALM_NAME=${REALM_NAME:-INGEST.EXAMPLE.COM}
KAFKA_SERVICE_HOST=${KAFKA_SERVICE_HOST:-localhost}
KAFKA_KEYTAB=${KAFKA_KEYTAB:-/etc/kafka_localhost.keytab}

echo "Using Active Directory KDC at ${AD_KDC_HOST} (realm ${REALM_NAME})"

# Render krb5.conf and JAAS for this AD realm / broker principal.
sed -e "s/\${REALM_NAME}/${REALM_NAME}/g" \
    -e "s/\${AD_KDC_HOST}/${AD_KDC_HOST}/g" \
    -e "s/\${AD_DOMAIN}/${AD_DOMAIN}/g" \
    /config/krb5.conf.template > /etc/krb5.conf

sed -e "s/\${REALM_NAME}/${REALM_NAME}/g" \
    -e "s|\${KAFKA_KEYTAB}|${KAFKA_KEYTAB}|g" \
    -e "s/\${KAFKA_SERVICE_HOST}/${KAFKA_SERVICE_HOST}/g" \
    /config/kafka_server_jaas.conf.template > /etc/kafka_server_jaas.conf

export KRB5_CONFIG=/etc/krb5.conf

if [[ ! -f "${KAFKA_KEYTAB}" ]]; then
    echo "ERROR: Kafka broker keytab not found at ${KAFKA_KEYTAB}"
    echo "Create principal kafka/${KAFKA_SERVICE_HOST}@${REALM_NAME} on AD and mount the keytab."
    echo "See testing/environments/docker/kafka_kerberos/README.md"
    exit 1
fi

echo "Checking reachability of AD KDC ${AD_KDC_HOST}:88"
wait_for_port 88 "${AD_KDC_HOST}" || {
    echo "ERROR: cannot reach AD Kerberos port 88 on ${AD_KDC_HOST}"
    echo "Open GCP firewall TCP/UDP 88 to this host."
    exit 1
}

echo "Starting ZooKeeper"
${KAFKA_HOME}/bin/zookeeper-server-start.sh ${KAFKA_HOME}/config/zookeeper.properties &
wait_for_port 2181

# INSIDE (9092): PLAINTEXT for healthchecks.
# SASL_OUTSIDE (9095): SASL_PLAINTEXT + GSSAPI against Active Directory.
echo "Starting Kafka broker with GSSAPI (AD KDC)"
mkdir -p "${KAFKA_LOGS_DIR}"

export KAFKA_OPTS="-Djava.security.auth.login.config=/etc/kafka_server_jaas.conf -Djava.security.krb5.conf=/etc/krb5.conf -Dsun.security.krb5.debug=true"

${KAFKA_HOME}/bin/kafka-server-start.sh ${KAFKA_HOME}/config/server.properties \
    --override delete.topic.enable=true \
    --override listener.security.protocol.map=INSIDE:PLAINTEXT,SASL_OUTSIDE:SASL_PLAINTEXT \
    --override listeners=INSIDE://0.0.0.0:9092,SASL_OUTSIDE://0.0.0.0:9095 \
    --override advertised.listeners=INSIDE://localhost:9092,SASL_OUTSIDE://localhost:9095 \
    --override inter.broker.listener.name=INSIDE \
    --override sasl.enabled.mechanisms=GSSAPI \
    --override sasl.kerberos.service.name=kafka \
    --override listener.name.sasl_outside.sasl.enabled.mechanisms=GSSAPI \
    --override listener.name.sasl_outside.gssapi.sasl.jaas.config="com.sun.security.auth.module.Krb5LoginModule required useKeyTab=true storeKey=true keyTab=\"${KAFKA_KEYTAB}\" principal=\"kafka/${KAFKA_SERVICE_HOST}@${REALM_NAME}\";" \
    --override logs.dir="${KAFKA_LOGS_DIR}" \
    --override log.flush.interval.ms=200 \
    --override num.partitions=3 \
    --override auto.leader.rebalance.enable=false \
    --override allow.everyone.if.no.acl.found=true &

wait_for_port 9092
wait_for_port 9095

echo "Kafka Kerberos broker is ready (AD KDC ${AD_KDC_HOST})"

tail -f /dev/null
