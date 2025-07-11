# Zero Trust Prototype Setup Script for Windows PowerShell
# Bu script Windows ortamında projeyi kurmanızı sağlar

Write-Host "🚀 Zero Trust Prototype Setup & Test (Windows)" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green

# Renk fonksiyonları
function Write-Success($message) {
    Write-Host "✅ $message" -ForegroundColor Green
}

function Write-Error($message) {
    Write-Host "❌ $message" -ForegroundColor Red
}

function Write-Info($message) {
    Write-Host "ℹ️  $message" -ForegroundColor Blue
}

function Write-Warning($message) {
    Write-Host "⚠️  $message" -ForegroundColor Yellow
}

# 1. Ön koşul kontrolü
Write-Info "Checking prerequisites..."

# Docker kontrolü
if (!(Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is not installed!"
    Write-Info "Please install Docker Desktop from: https://www.docker.com/products/docker-desktop/"
    exit 1
}

# Docker Compose kontrolü
if (!(Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-Error "Docker Compose is not installed!"
    Write-Info "Please install Docker Compose"
    exit 1
}

Write-Success "Prerequisites check passed"

# 2. SSL sertifikası oluştur (Windows için)
Write-Info "Generating SSL certificates..."

# SSL dizini oluştur
if (!(Test-Path "nginx\ssl")) {
    New-Item -ItemType Directory -Path "nginx\ssl" -Force
}

# OpenSSL kontrolü
if (Get-Command openssl -ErrorAction SilentlyContinue) {
    Write-Info "Using OpenSSL to generate certificates..."
    
    # Private key oluştur
    openssl genrsa -out nginx\ssl\server.key 2048
    
    # Certificate signing request oluştur
    openssl req -new -key nginx\ssl\server.key -out nginx\ssl\server.csr -subj "/C=TR/ST=Istanbul/L=Istanbul/O=Zero Trust Organization/OU=IT Department/CN=localhost"
    
    # Self-signed certificate oluştur
    openssl x509 -req -days 365 -in nginx\ssl\server.csr -signkey nginx\ssl\server.key -out nginx\ssl\server.crt
    
    # CSR dosyasını sil
    Remove-Item nginx\ssl\server.csr
    
    Write-Success "SSL certificates generated successfully!"
} else {
    Write-Warning "OpenSSL not found. Creating dummy certificates..."
    
    # Dummy certificates (development only)
    @"
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKZM1mxK8Z4fMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTE1MTAwMDAwWhcNMjUwMTE1MTAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAy8DbkXxKEiHQXWJhpDO4RRPvMBELHgOZbHbQRJAH0LKhcJ2gZzWfzWFq
aXAzZSIUhzFoIIJYJWQQBVIwMDUxMhU1CwE5G6kgTSMPwJXuTQJJoZiNAWGK/Y8I
kGxsIcvwPqsxvDFjZL6jAzL8rNz+hRHzPyLkRTQdcFrEOcJsY0JdO6ZS9hJFBGkP
YqBPnIgR/qGkH3vPPpMgKWEBkVgGVyaY4bVvBvVqGzgNz1BcJTHGBKfBzEGYlFHH
bZNvPvFuXyGkFxqmCtfDKnBFgFmxHEDFOFTULLPv5KjdmT4XBnfAiHSAkIWJBNKx
SHgHhqNnVZl5LHyPcZBVwLZmCYMKswIDAQABo1AwTjAdBgNVHQ4EFgQU7V7zQjdK
fK6nFdF7Z8D4oGQP4qEwHwYDVR0jBBgwFoAU7V7zQjdKfK6nFdF7Z8D4oGQP4qEw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAh5WTGXgzNYfKtBjKwm3o
GrIBEEzgFGxbNGWNnhEiLKnQCwpqNLI5XqQjwGlV6JyTJI4+9VlVOQJkTpZOOYmF
TfZTdKMSLqGhEGZWPeGhXdIR/8tHGjzYAqLaWOPiPbRZPOQlKIJNYhxqVGWMJZqr
HmNgGzwD4rXNpIqvRnVfEGP4eOMRHOXIZmGhOVZFEZXPNkSGhkMGCKU7wJ8VTmvP
TcV0lhqKQBnVZjCKFXkKMFvdYK5f0KLuPBmnZZFOE0GhgwJnqHMzFLMlBmEzSQKJ
LiEuWEzKEG4gNlYl1cRgMkzjQ5oNh4VnxzlMJcZgkzBIH3/tTvIJJFrHZeGhXJeG
h1VZYGvdnILwFKkGJhYjEw==
-----END CERTIFICATE-----
"@ | Out-File -FilePath "nginx\ssl\server.crt" -Encoding ASCII

    @"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDLwNuRfEoSIdBd
YmGkM7hFE+8wEQseA5lsdtBEkAfQsqFwnaJnNZ/NYWppcDNlIhSHMWgggllJZhAF
UjAwNTEyFTULATkbqSBNIw/Ale5NAkmhmI0BYYr9jwiQbGwhy/A+qzG8MWNkvqMD
MvzPzH6FEfM/IuRFNB1wWsQ5wmxjQl07plL2EkUEaQ9ioE+ciBH+oaQfe88+kyAp
YQGRWAZXJPZ7lNGKrZaZmplN4lEqbSNDlvNSM2zrJCMJmTNwTi6sj5JFh7j5pIqv
RnVfEGP4eOMRHOXIZmGhOVZFEZXPNkSGhkMGCKU7wJ8VTmvPTcV0lhqKQBnVZjCK
FXkKMFvdYK5f0KLuPBmnZZFOE0GhgwJnqHMzFLMlBmEzSQKJLiEuWEzKEG4gNlYl
1cRgMkzjQ5oNh4VnxzlMJcZgkzBIH3/tTvIJJFrHZeGhXJeGh1VZYGvdnILwFKkG
JhYjEwIDAQABAoIBAHNK8RBGqZGwwGQzNjzlG6bsXEEOHcBbWVKjPQFzOyOvvZZD
0+/SshNPyLZlEiNOhiFmkOPFYEJ2TQfXhSNWyGvlCLGJW/ZPIQdkwwBcQzBdnTz3
XZsLnfZEwBEPmtKF6aHCITMdkzZHIWgGNYbFuoJhGGvJGdcYN5MhYVEQNdoGIhKt
NZmZPUG4TBgRQZ9tJQXYmNbdxeHEwdKiNHF9KgYOmWTJdIvNT3L8EEpvZcRVQMmD
9BYKvLQJfFZvSdWcIQaKGEJLCqEFJPaLKcbLZZaRQGZCEkPJ4aKDvKMSJ4QdpCq9
eQaVFGIWQKzFHNIJkIgIlHQvqiKhcIQiJIRRhQ5LKQfQhJEbVGEDcZRGUJAoGBAP
T4J1mZvUmLXhVJ8lEMO8zOCO6pnSEfJwI/JYZvJ0QdMQZcEyRCvXhJ4cCJxwLdH9
jrEjhPMmjN2J6bEkxQ8pMvKfCnJ6KpKPiKqIBnS5OLZOAjWfvqhVQDJgXN5Bm0gK
VvXBCwXYCFWAjcKsyUfQIEVFUGNgOYAOoQFRQaVOhWkqc8sOqmjdHlXOoKAFaWQY
WoNhfCrIjnQCgYEA0YmQFyAMgNKDqvJ6fQBnAeNPjxSHnQp2XmJwUvmAWO8fQkZy
dHJjYnNyZlmRjlWdJQYkNKEOELGRYBGkbQC7mzJvJ1tMiGgZMRQgSoZ4XC5tGnN1
mPiJjCqpTGhzJrNGvfLHxIKrqJqoQoLzIZkJjgECgYEAvfkiPgRwdQrGDvfTjyNJ
gOHFKqXqjy4WZUPuRXRyiUOJJb5TGiZGKAQHpqMNPNBgKZuQAMRxQJWNnYEJUjGU
hKnvdcVALdMrXgWXtU+vRWKEZNDPeIzFNxwYfOI0JRqKQRqnYCLnwZqnUKJCrXGp
QUXOLCQXGiZHZQCgYEAjUEKbJhFJJBgdXdAqhHzBECGXoFKLwdJSJzMfOoWgBqON
GvRAMvqMFxjdFl4qb2aGlQHbJZaQYXJwUEsJOCfGWRZYEKjXLdRKSCJdGQOGnLzJ
VHJpnMLMjCEEhLzlYxuLvECgYEAjFJRF4kIiUJr4tAKYUQZSVGkGEYaHNdMcuHn
XOoKAFaWQYWoNhfCrIjnQCgYEA0YmQFyAMgNKDqvJ6fQBnAeNPjxSHnQp2XmJwUv
mAWO8fQkZydHJjYnNyZlmRjlWdJQYkNKEOELGRYBGkbQC7mzJvJ1tMiGgZMRQgSo
Z4XC5tGnN1mPiJjCqpTGhzJrNGvfLHxIKrqJqoQoLzIZkJjgECgYEAvfkiPgRwdQ
rGDvfTjyNJgOHFKqXqjy4WZUPuRXRyiUOJJb5TGiZGKAQHpqMNPNBgKZuQAMRxQJ
WNnYEJUjGUhKnvdcVALdMrXgWXtU+vRWKEZNDPeIzFNxwYfOI0JRqKQRqnYCLnwZ
qnUKJCrXGpQUXOLCQXGiZHZQ==
-----END PRIVATE KEY-----
"@ | Out-File -FilePath "nginx\ssl\server.key" -Encoding ASCII

    Write-Warning "Using dummy certificates for development"
}

# 3. Mevcut container'ları temizle
Write-Info "Cleaning up existing containers..."
docker-compose down -v --remove-orphans

# 4. Docker image'larını build et
Write-Info "Building Docker images..."
docker-compose build --no-cache

# 5. Servisleri başlat
Write-Info "Starting services..."
docker-compose up -d

# 6. Servislerin hazır olmasını bekle
Write-Info "Waiting for services to be ready..."
Start-Sleep -Seconds 60

# 7. Servis durumlarını kontrol et
Write-Info "Checking service health..."

$services = @(
    @{name="keycloak"; port=8080},
    @{name="user-service"; port=5001},
    @{name="admin-service"; port=5002},
    @{name="security-test-service"; port=5003}
)

foreach ($service in $services) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$($service.port)/health" -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -eq 200) {
            Write-Success "$($service.name) is healthy"
        } else {
            Write-Error "$($service.name) is not responding properly"
        }
    } catch {
        Write-Error "$($service.name) is not responding"
    }
}

# 8. Temel güvenlik testleri
Write-Info "Running basic security tests..."

# Test 1: Unauthorized access
Write-Host "Test 1: Unauthorized access to user service"
try {
    $response = Invoke-WebRequest -Uri "http://localhost:5001/info" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 401) {
        Write-Success "Unauthorized access correctly blocked"
    } else {
        Write-Error "Unauthorized access not blocked"
    }
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Success "Unauthorized access correctly blocked"
    } else {
        Write-Error "Unexpected error: $($_.Exception.Message)"
    }
}

# Test 2: Invalid token
Write-Host "Test 2: Invalid token access"
try {
    $headers = @{
        "Authorization" = "Bearer invalid_token"
    }
    $response = Invoke-WebRequest -Uri "http://localhost:5001/info" -Headers $headers -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 401) {
        Write-Success "Invalid token correctly rejected"
    } else {
        Write-Error "Invalid token not rejected"
    }
} catch {
    if ($_.Exception.Response.StatusCode -eq 401) {
        Write-Success "Invalid token correctly rejected"
    } else {
        Write-Error "Unexpected error: $($_.Exception.Message)"
    }
}

# Test 3: Health endpoints
Write-Host "Test 3: Health endpoints accessibility"
try {
    $response = Invoke-WebRequest -Uri "http://localhost:5001/health" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Success "Health endpoints accessible"
    } else {
        Write-Error "Health endpoints not accessible"
    }
} catch {
    Write-Error "Health endpoints not accessible"
}

# 9. Keycloak setup rehberi
Write-Info "Setting up Keycloak..."
Write-Host ""
Write-Host "🔑 Keycloak Setup Instructions:" -ForegroundColor Yellow
Write-Host "1. Open http://localhost:8080/admin" -ForegroundColor White
Write-Host "2. Login with: admin/admin" -ForegroundColor White
Write-Host "3. Create a new realm: 'zero-trust'" -ForegroundColor White
Write-Host "4. Create users with appropriate roles" -ForegroundColor White
Write-Host "5. Configure client settings" -ForegroundColor White
Write-Host ""

# 10. Test senaryoları
Write-Info "Test scenarios available:"
Write-Host ""
Write-Host "📋 Available Test Endpoints:" -ForegroundColor Yellow
Write-Host "• Health Check: http://localhost:5001/health" -ForegroundColor White
Write-Host "• User Service: http://localhost:5001/info (requires auth)" -ForegroundColor White
Write-Host "• Admin Service: http://localhost:5002/admin (requires admin role)" -ForegroundColor White
Write-Host "• Security Tests: http://localhost:5003/security-test/start (requires admin role)" -ForegroundColor White
Write-Host ""
Write-Host "🔐 Authentication Flow:" -ForegroundColor Yellow
Write-Host "1. Get token from Keycloak: http://localhost:8080/auth/realms/master/protocol/openid-connect/token" -ForegroundColor White
Write-Host "2. Use token in Authorization header: 'Bearer <token>'" -ForegroundColor White
Write-Host ""

# 11. Monitoring
Write-Info "Monitoring URLs:"
Write-Host "• Prometheus: http://localhost:9090" -ForegroundColor White
Write-Host "• Grafana: http://localhost:3000 (admin/admin)" -ForegroundColor White
Write-Host ""

# 12. Logs
Write-Info "Viewing logs:"
Write-Host "• All services: docker-compose logs -f" -ForegroundColor White
Write-Host "• Specific service: docker-compose logs -f <service-name>" -ForegroundColor White
Write-Host ""

# 13. Cleanup
Write-Info "Cleanup commands:"
Write-Host "• Stop services: docker-compose down" -ForegroundColor White
Write-Host "• Remove volumes: docker-compose down -v" -ForegroundColor White
Write-Host "• Remove everything: docker-compose down -v --remove-orphans" -ForegroundColor White
Write-Host ""

Write-Success "Zero Trust Prototype is ready!"
Write-Host ""
Write-Host "🎯 Next Steps:" -ForegroundColor Yellow
Write-Host "1. Configure Keycloak realm and users" -ForegroundColor White
Write-Host "2. Test authentication flows" -ForegroundColor White
Write-Host "3. Run security tests" -ForegroundColor White
Write-Host "4. Review audit logs" -ForegroundColor White
Write-Host "5. Check monitoring dashboards" -ForegroundColor White
Write-Host ""
Write-Host "📚 Documentation: Check README.md for detailed instructions" -ForegroundColor Yellow

# Kullanıcıdan devam etmek isteyip istemediğini sor
Write-Host ""
$continue = Read-Host "Press Enter to continue or 'q' to quit"
if ($continue -eq 'q') {
    exit
}

Write-Host "🚀 Setup completed successfully!" -ForegroundColor Green
