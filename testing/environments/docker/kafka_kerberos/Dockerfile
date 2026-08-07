# Kafka + Active Directory (GSSAPI) test container
#
# Kafka broker with SASL/GSSAPI. The KDC is the cloud Active Directory DC
# (not an in-container MIT krb5kdc).
#
# Default AD endpoint (override via compose env):
#   AD_KDC_HOST=[VM-IP]
#   REALM_NAME=INGEST.EXAMPLE.COM
#   AD_DOMAIN=ingest.example.com
#
# Host ports:
#   9095 - SASL_PLAINTEXT / GSSAPI

FROM debian:bookworm

ENV KAFKA_HOME=/kafka
ENV KAFKA_LOGS_DIR=/kafka-logs
ENV KAFKA_VERSION=3.6.0
ENV _JAVA_OPTIONS="-Djava.net.preferIPv4Stack=true"
ENV TERM=linux

ENV AD_KDC_HOST=[VM-IP]
ENV AD_DOMAIN=ingest.example.com
ENV REALM_NAME=INGEST.EXAMPLE.COM
ENV KAFKA_SERVICE_HOST=localhost
ENV KAFKA_KEYTAB=/etc/kafka_localhost.keytab
ENV BEATS_USER=beats
ENV BEATS_PASSWORD=Testing1!

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl openjdk-17-jre-headless netcat-openbsd \
      krb5-user \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p ${KAFKA_LOGS_DIR} ${KAFKA_HOME} && \
    curl -J -L -s -f -o /tmp/kafka.tgz \
      "https://archive.apache.org/dist/kafka/${KAFKA_VERSION}/kafka_2.13-${KAFKA_VERSION}.tgz" && \
    tar xzf /tmp/kafka.tgz -C ${KAFKA_HOME} --strip-components 1 && \
    rm /tmp/kafka.tgz

ADD config /config
ADD run.sh /run.sh
ADD healthcheck.sh /healthcheck.sh

RUN chmod +x /run.sh /healthcheck.sh

EXPOSE 9092 9095

HEALTHCHECK --start-period=60s --interval=10s --timeout=15s --retries=36 CMD /healthcheck.sh

ENTRYPOINT ["/run.sh"]
