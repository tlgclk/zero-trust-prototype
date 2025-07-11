FROM prom/prometheus:latest

# Copy prometheus configuration
COPY monitoring/prometheus.yml /etc/prometheus/prometheus.yml

# Default command with configuration
CMD ["--config.file=/etc/prometheus/prometheus.yml", \
     "--storage.tsdb.path=/prometheus", \
     "--web.console.libraries=/etc/prometheus/console_libraries", \
     "--web.console.templates=/etc/prometheus/consoles", \
     "--storage.tsdb.retention.time=200h", \
     "--web.enable-lifecycle"]
