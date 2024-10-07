#!/bin/sh

# Substitute environment variables in the Alertmanager configuration template
envsubst < /etc/alertmanager/alertmanager.yml.tpl > /etc/alertmanager/alertmanager.yml

# Start Prometheus
/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus \
  --web.listen-address=:9090 \
  --web.config.file=/etc/prometheus/web-config.yml &

# Start Alertmanager without HTTPS
/usr/local/bin/alertmanager \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --storage.path=/var/lib/alertmanager \
  --web.listen-address=:9093 \
  --web.config.file=/etc/alertmanager/web-config.yml &

# Wait for all background jobs to finish
wait