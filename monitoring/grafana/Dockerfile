FROM grafana/grafana:latest

# Copy provisioning configuration with unified alerting
COPY monitoring/grafana/provisioning/datasources /etc/grafana/provisioning/datasources
COPY monitoring/grafana/provisioning/dashboards /etc/grafana/provisioning/dashboards
COPY monitoring/grafana/provisioning/alerting/unified-alerts.yml /etc/grafana/provisioning/alerting/alerts.yml

# Use default Grafana entrypoint
