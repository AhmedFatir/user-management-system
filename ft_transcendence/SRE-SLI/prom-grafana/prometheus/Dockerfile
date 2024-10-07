FROM debian:bullseye

RUN apt-get update && apt-get install -y \
    wget curl \
    ca-certificates \
    gnupg \
    openssl \
    apt-transport-https \
    software-properties-common \
    gettext-base \
    && rm -rf /var/lib/apt/lists/*

# Create Prometheus user and directories
RUN useradd --no-create-home --shell /bin/false prometheus \
    && mkdir -p /etc/prometheus /var/lib/prometheus /etc/alertmanager /var/lib/alertmanager \
    && chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus /etc/alertmanager /var/lib/alertmanager

# Download and install Prometheus
RUN wget https://github.com/prometheus/prometheus/releases/download/v2.40.0/prometheus-2.40.0.linux-amd64.tar.gz \
    && tar -xvzf prometheus-2.40.0.linux-amd64.tar.gz \
    && cp prometheus-2.40.0.linux-amd64/prometheus /usr/local/bin/ \
    && cp prometheus-2.40.0.linux-amd64/promtool /usr/local/bin/ \
    && cp -r prometheus-2.40.0.linux-amd64/consoles /etc/prometheus/ \
    && cp -r prometheus-2.40.0.linux-amd64/console_libraries /etc/prometheus/ \
    && cp prometheus-2.40.0.linux-amd64/prometheus.yml /etc/prometheus/ \
    && chown -R prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool /etc/prometheus/consoles /etc/prometheus/console_libraries \
    && rm -rf prometheus-2.40.0.linux-amd64*

# Download and install Alertmanager
RUN wget https://github.com/prometheus/alertmanager/releases/download/v0.25.0/alertmanager-0.25.0.linux-amd64.tar.gz \
    && tar -xvzf alertmanager-0.25.0.linux-amd64.tar.gz \
    && cp alertmanager-0.25.0.linux-amd64/alertmanager /usr/local/bin/ \
    && cp alertmanager-0.25.0.linux-amd64/amtool /usr/local/bin/ \
    && cp -r alertmanager-0.25.0.linux-amd64/alertmanager.yml /etc/alertmanager/ \
    && chown -R prometheus:prometheus /usr/local/bin/alertmanager /usr/local/bin/amtool /etc/alertmanager/ \
    && rm -rf alertmanager-0.25.0.linux-amd64*

# Generate a self-signed SSL certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/prometheus/prometheus.key \
    -out /etc/prometheus/prometheus.crt \
    -subj "/C=MO/ST=KH/L=KH/O=1337/OU=1337/CN=localhost/UID=user"

# Copy SSL certificates to Alertmanager directory
RUN cp /etc/prometheus/prometheus.key /etc/alertmanager/alertmanager.key \
    && cp /etc/prometheus/prometheus.crt /etc/alertmanager/alertmanager.crt

# Grant SSL permissions to prometheus user
RUN chown prometheus:prometheus /etc/prometheus/prometheus.key /etc/prometheus/prometheus.crt \
    /etc/alertmanager/alertmanager.key /etc/alertmanager/alertmanager.crt \
    && chmod 600 /etc/prometheus/prometheus.key /etc/prometheus/prometheus.crt \
    /etc/alertmanager/alertmanager.key /etc/alertmanager/alertmanager.crt

# Set working directory
WORKDIR /etc/prometheus

# Copy startup script and alertmanager configuration template
COPY ./prom-config/start_services.sh /usr/local/bin/start_services.sh
COPY ./alert-config/alertmanager.yml.tpl /etc/alertmanager/alertmanager.yml.tpl

# Make the startup script executable
RUN chmod +x /usr/local/bin/start_services.sh

# Run Prometheus and Alertmanager as a non-root user
USER prometheus

# Start both Prometheus and Alertmanager using a startup script
CMD ["/usr/local/bin/start_services.sh"]
