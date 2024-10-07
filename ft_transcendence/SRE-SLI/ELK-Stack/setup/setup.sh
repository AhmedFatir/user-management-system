#!/bin/bash

if [ -z "${ELASTIC_PASSWORD}" ] || [ -z "${KIBANA_PASSWORD}" ]; then
    echo "Set the ELASTIC_PASSWORD and KIBANA_PASSWORD environment variables in the .env file"
    exit 1
fi

if [ ! -f config/certs/ca.zip ]; then
    echo "Creating CA"
    bin/elasticsearch-certutil ca --silent --pem -out config/certs/ca.zip
    unzip config/certs/ca.zip -d config/certs
fi

if [ ! -f config/certs/certs.zip ]; then
    echo "Creating certs"
    cat > config/certs/instances.yml <<EOL
instances:
  - name: elasticsearch
    dns:
      - elasticsearch
      - localhost
    ip:
      - 127.0.0.1
  - name: kibana
    dns:
      - kibana
      - localhost
    ip:
      - 127.0.0.1
  - name: logstash
    dns:
      - logstash
      - localhost
    ip:
      - 127.0.0.1
EOL
    echo "Creating certs for elasticsearch, kibana, and logstash"
    bin/elasticsearch-certutil cert --silent --pem -out config/certs/certs.zip --in \
      config/certs/instances.yml --ca-cert config/certs/ca/ca.crt --ca-key config/certs/ca/ca.key
    unzip config/certs/certs.zip -d config/certs
fi

echo "Setting file permissions"
chown -R root:root config/certs
find config/certs -type d -exec chmod 750 {} \;
find config/certs -type f -exec chmod 640 {} \;

echo "Waiting for Elasticsearch availability"
until curl -s --cacert config/certs/ca/ca.crt https://elasticsearch:9200 \
  | grep -q "missing authentication credentials"; do sleep 5; done

echo "stting Kiabana password"
until curl -s \
  -X POST https://elasticsearch:9200/_security/user/kibana_system/_password \
  --cacert config/certs/ca/ca.crt \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" \
  | grep -q "^{}"; do sleep 5; done

echo "Importing kibana Dashboard"
until curl -s -k \
    -X POST "https://kibana:5601/api/saved_objects/_import" \
    -u "elastic:${ELASTIC_PASSWORD}" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: multipart/form-data" \
    --form file=@/usr/share/elasticsearch/config/dashboard.ndjson \
    | grep -q '"success":true'; do sleep 5; echo "Waiting for import..."; done;

echo "All done!, removing the setup container"
CONTAINER_ID=$(hostname)
curl --unix-socket /var/run/docker.sock -X DELETE "http://localhost/containers/${CONTAINER_ID}?force=true"
