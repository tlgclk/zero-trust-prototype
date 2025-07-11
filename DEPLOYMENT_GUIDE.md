# Deployment Guide - Zero Trust Prototype

## Production Deployment Checklist

### Pre-deployment Requirements

1. **Infrastructure Requirements**
   - Docker 20.10+ ve Docker Compose v2+
   - En az 8GB RAM (production workload için)
   - En az 20GB disk space
   - SSL sertifikaları (Let's Encrypt veya commercial)
   - Domain name ve DNS konfigürasyonu

2. **Security Requirements**
   - Firewall konfigürasyonu
   - Network segmentation
   - Backup strategy
   - Log aggregation solution
   - Monitoring ve alerting setup

### Environment Configuration

#### 1. Production Environment Variables

`.env.production` dosyası oluşturun:

```bash
# Keycloak Production Settings
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=StrongAdminPassword123!
KC_DB=postgres
KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak
KC_DB_USERNAME=keycloak_prod
KC_DB_PASSWORD=VeryStrongDBPassword456!
KC_HOSTNAME=auth.yourdomain.com
KC_HOSTNAME_STRICT=true
KC_PROXY=edge

# PostgreSQL Production Settings
POSTGRES_DB=keycloak
POSTGRES_USER=keycloak_prod
POSTGRES_PASSWORD=VeryStrongDBPassword456!

# Flask Production Settings
FLASK_ENV=production
FLASK_DEBUG=false
SECRET_KEY=YourVeryLongAndSecretKeyHere789!

# SSL Settings
SSL_CERT_PATH=/etc/ssl/certs/yourdomain.crt
SSL_KEY_PATH=/etc/ssl/private/yourdomain.key

# External URLs
EXTERNAL_KEYCLOAK_URL=https://auth.yourdomain.com
EXTERNAL_API_URL=https://api.yourdomain.com
```

#### 2. Production Docker Compose Override

`docker-compose.prod.yml` oluşturun:

```yaml
version: '3.8'

services:
  keycloak:
    environment:
      - KC_HOSTNAME=auth.yourdomain.com
      - KC_HOSTNAME_STRICT=true
      - KC_PROXY=edge
      - KC_HTTP_ENABLED=false
      - KC_HTTPS_PORT=8443
    volumes:
      - ./ssl:/opt/keycloak/conf/ssl:ro
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 1G
          cpus: '0.5'

  postgres:
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '0.5'

  nginx:
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./ssl:/etc/ssl/certs:ro
      - ./nginx/nginx.prod.conf:/etc/nginx/nginx.conf:ro
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.25'

  user-service:
    environment:
      - FLASK_ENV=production
      - KEYCLOAK_URL=${EXTERNAL_KEYCLOAK_URL}
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  admin-service:
    environment:
      - FLASK_ENV=production
      - KEYCLOAK_URL=${EXTERNAL_KEYCLOAK_URL}
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 512M
          cpus: '0.5'

  security-test-service:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '0.5'

volumes:
  postgres_data:
    driver: local
```

#### 3. Production Nginx Configuration

`nginx/nginx.prod.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream user_service {
        server user-service:5000;
    }
    
    upstream admin_service {
        server admin-service:5000;
    }
    
    upstream security_service {
        server security-test-service:5000;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name api.yourdomain.com auth.yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    # API Gateway
    server {
        listen 443 ssl http2;
        server_name api.yourdomain.com;

        ssl_certificate /etc/ssl/certs/yourdomain.crt;
        ssl_certificate_key /etc/ssl/certs/yourdomain.key;

        # API Rate limiting
        limit_req zone=api burst=20 nodelay;

        location /api/user/ {
            proxy_pass http://user_service/;
            include proxy_params;
        }

        location /api/admin/ {
            proxy_pass http://admin_service/;
            include proxy_params;
        }

        location /api/security/ {
            proxy_pass http://security_service/;
            include proxy_params;
        }
    }

    # Keycloak Proxy
    server {
        listen 443 ssl http2;
        server_name auth.yourdomain.com;

        ssl_certificate /etc/ssl/certs/yourdomain.crt;
        ssl_certificate_key /etc/ssl/certs/yourdomain.key;

        # Login rate limiting
        location /realms/zero-trust/protocol/openid-connect/token {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://keycloak:8080;
            include proxy_params;
        }

        location / {
            proxy_pass http://keycloak:8080;
            include proxy_params;
        }
    }
}
```

### SSL Certificate Setup

#### Let's Encrypt with Certbot

```bash
# Install certbot
sudo apt-get update
sudo apt-get install certbot

# Get certificates
sudo certbot certonly --standalone -d api.yourdomain.com -d auth.yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./ssl/yourdomain.crt
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./ssl/yourdomain.key

# Set proper permissions
sudo chown root:root ./ssl/*
sudo chmod 600 ./ssl/yourdomain.key
sudo chmod 644 ./ssl/yourdomain.crt
```

#### Certificate Renewal Script

`scripts/renew-certs.sh`:

```bash
#!/bin/bash

# Renew certificates
certbot renew --quiet

# Copy new certificates
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ./ssl/yourdomain.crt
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ./ssl/yourdomain.key

# Reload Nginx
docker-compose exec nginx nginx -s reload

echo "Certificates renewed at $(date)"
```

Crontab entry:
```bash
0 3 * * 0 /path/to/zero-trust-prototype/scripts/renew-certs.sh >> /var/log/cert-renewal.log 2>&1
```

### Database Backup Strategy

#### Automated Backup Script

`scripts/backup-db.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="keycloak_backup_$DATE.sql"

# Create backup
docker-compose exec postgres pg_dump -U keycloak_prod keycloak > $BACKUP_DIR/$BACKUP_FILE

# Compress backup
gzip $BACKUP_DIR/$BACKUP_FILE

# Remove backups older than 30 days
find $BACKUP_DIR -name "keycloak_backup_*.sql.gz" -mtime +30 -delete

echo "Database backup completed: $BACKUP_FILE.gz"
```

Crontab entry:
```bash
0 2 * * * /path/to/zero-trust-prototype/scripts/backup-db.sh >> /var/log/db-backup.log 2>&1
```

### Monitoring Setup

#### Production Prometheus Configuration

`monitoring/prometheus.prod.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'keycloak'
    static_configs:
      - targets: ['keycloak:8080']
    metrics_path: '/metrics'

  - job_name: 'user-service'
    static_configs:
      - targets: ['user-service:5000']
    metrics_path: '/metrics'

  - job_name: 'admin-service'
    static_configs:
      - targets: ['admin-service:5000']
    metrics_path: '/metrics'

  - job_name: 'security-test-service'
    static_configs:
      - targets: ['security-test-service:5000']
    metrics_path: '/metrics'

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx:80']
    metrics_path: '/metrics'

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
```

#### Alert Rules

`monitoring/alert_rules.yml`:

```yaml
groups:
  - name: zero-trust-alerts
    rules:
      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.instance }} is down"

      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate on {{ $labels.instance }}"

      - alert: AuthenticationFailures
        expr: rate(keycloak_failed_login_attempts[5m]) > 10
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
```

### Security Hardening

#### 1. Container Security

`docker-compose.security.yml`:

```yaml
version: '3.8'

services:
  keycloak:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /opt/keycloak/data/tmp

  user-service:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /app/logs

  admin-service:
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /app/logs
```

#### 2. Network Security

```yaml
networks:
  frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  backend:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.21.0.0/24
```

### Deployment Commands

#### 1. Production Deployment

```bash
#!/bin/bash

# Pull latest images
docker-compose -f docker-compose.yml -f docker-compose.prod.yml pull

# Build custom images
docker-compose -f docker-compose.yml -f docker-compose.prod.yml build

# Deploy with zero downtime
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Wait for services to be healthy
./scripts/wait-for-health.sh

# Run post-deployment tests
./scripts/post-deployment-tests.sh

echo "Production deployment completed successfully"
```

#### 2. Health Check Script

`scripts/wait-for-health.sh`:

```bash
#!/bin/bash

SERVICES=("keycloak:8080/health" "user-service:5000/health" "admin-service:5000/health" "security-test-service:5000/health")

for service in "${SERVICES[@]}"; do
    echo "Waiting for $service to be healthy..."
    
    for i in {1..30}; do
        if curl -f "http://$service" > /dev/null 2>&1; then
            echo "$service is healthy"
            break
        fi
        
        if [ $i -eq 30 ]; then
            echo "$service failed to become healthy"
            exit 1
        fi
        
        sleep 10
    done
done

echo "All services are healthy"
```

#### 3. Rolling Update Script

`scripts/rolling-update.sh`:

```bash
#!/bin/bash

SERVICES=("user-service" "admin-service" "security-test-service")

for service in "${SERVICES[@]}"; do
    echo "Updating $service..."
    
    # Scale up new instance
    docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale $service=2 $service
    
    # Wait for health check
    sleep 30
    
    # Scale down old instance
    docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale $service=1 $service
    
    echo "$service updated successfully"
done
```

### Maintenance

#### 1. Log Rotation

`/etc/logrotate.d/zero-trust`:

```
/var/log/zero-trust/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    postrotate
        docker-compose exec nginx nginx -s reopen
    endscript
}
```

#### 2. Monitoring Cleanup

`scripts/cleanup-metrics.sh`:

```bash
#!/bin/bash

# Clean old Prometheus data (older than 30 days)
docker-compose exec prometheus rm -rf /prometheus/data/wal/*

# Clean old logs
find /var/log/zero-trust -name "*.log" -mtime +30 -delete

echo "Cleanup completed at $(date)"
```

### Disaster Recovery

#### 1. Full System Backup

```bash
#!/bin/bash

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_ROOT="/backups/full_backup_$BACKUP_DATE"

mkdir -p $BACKUP_ROOT

# Database backup
docker-compose exec postgres pg_dump -U keycloak_prod keycloak | gzip > $BACKUP_ROOT/database.sql.gz

# Configuration backup
tar -czf $BACKUP_ROOT/config.tar.gz docker-compose.yml nginx/ monitoring/ ssl/

# Application data backup
docker-compose exec keycloak tar -czf - /opt/keycloak/data > $BACKUP_ROOT/keycloak_data.tar.gz

echo "Full backup completed: $BACKUP_ROOT"
```

#### 2. System Restore

```bash
#!/bin/bash

BACKUP_DIR=$1

if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup_directory>"
    exit 1
fi

# Stop services
docker-compose down

# Restore configuration
tar -xzf $BACKUP_DIR/config.tar.gz

# Restore database
gunzip < $BACKUP_DIR/database.sql.gz | docker-compose exec -T postgres psql -U keycloak_prod keycloak

# Restore application data
docker-compose exec -T keycloak tar -xzf - -C / < $BACKUP_DIR/keycloak_data.tar.gz

# Start services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

echo "System restore completed from: $BACKUP_DIR"
```

### Production Checklist

- [ ] SSL certificates configured and valid
- [ ] DNS records pointing to correct servers
- [ ] Firewall rules configured
- [ ] Database backups automated
- [ ] Log rotation configured
- [ ] Monitoring and alerting active
- [ ] Security scanning scheduled
- [ ] Performance baseline established
- [ ] Disaster recovery tested
- [ ] Documentation updated
- [ ] Team training completed
