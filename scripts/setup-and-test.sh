#!/bin/bash

# Zero Trust Prototype Setup and Test Script
# Bu script projeyi başlatır ve temel testleri çalıştırır

echo "🚀 Zero Trust Prototype Setup & Test"
echo "===================================="

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonksiyon: Başarı mesajı
success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Fonksiyon: Hata mesajı
error() {
    echo -e "${RED}❌ $1${NC}"
}

# Fonksiyon: Bilgi mesajı
info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Fonksiyon: Uyarı mesajı
warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# 1. Ön koşul kontrolü
info "Checking prerequisites..."

# Docker kontrolü
if ! command -v docker &> /dev/null; then
    error "Docker is not installed!"
    exit 1
fi

# Docker Compose kontrolü
if ! command -v docker-compose &> /dev/null; then
    error "Docker Compose is not installed!"
    exit 1
fi

success "Prerequisites check passed"

# 2. SSL sertifikası oluştur
info "Generating SSL certificates..."
chmod +x scripts/generate-ssl.sh
./scripts/generate-ssl.sh

# 3. Mevcut container'ları temizle
info "Cleaning up existing containers..."
docker-compose down -v --remove-orphans

# 4. Docker image'larını build et
info "Building Docker images..."
docker-compose build --no-cache

# 5. Servisleri başlat
info "Starting services..."
docker-compose up -d

# 6. Servislerin hazır olmasını bekle
info "Waiting for services to be ready..."
sleep 60

# 7. Servis durumlarını kontrol et
info "Checking service health..."

services=("keycloak:8080" "user-service:5000" "admin-service:5000" "security-test-service:5000")

for service in "${services[@]}"; do
    IFS=':' read -r name port <<< "$service"
    
    if curl -f -s "http://localhost:$port/health" > /dev/null 2>&1; then
        success "$name is healthy"
    else
        error "$name is not responding"
    fi
done

# 8. Temel güvenlik testleri
info "Running basic security tests..."

# Test 1: Unauthorized access
echo "Test 1: Unauthorized access to user service"
if curl -s -o /dev/null -w "%{http_code}" "http://localhost:5001/info" | grep -q "401"; then
    success "Unauthorized access correctly blocked"
else
    error "Unauthorized access not blocked"
fi

# Test 2: Invalid token
echo "Test 2: Invalid token access"
if curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid_token" "http://localhost:5001/info" | grep -q "401"; then
    success "Invalid token correctly rejected"
else
    error "Invalid token not rejected"
fi

# Test 3: Health endpoints
echo "Test 3: Health endpoints accessibility"
if curl -s -f "http://localhost:5001/health" > /dev/null; then
    success "Health endpoints accessible"
else
    error "Health endpoints not accessible"
fi

# 9. Keycloak setup rehberi
info "Setting up Keycloak..."
echo ""
echo "🔑 Keycloak Setup Instructions:"
echo "1. Open http://localhost:8080/admin"
echo "2. Login with: admin/admin"
echo "3. Create a new realm: 'zero-trust'"
echo "4. Create users with appropriate roles"
echo "5. Configure client settings"
echo ""

# 10. Test senaryoları
info "Test scenarios available:"
echo ""
echo "📋 Available Test Endpoints:"
echo "• Health Check: http://localhost:5001/health"
echo "• User Service: http://localhost:5001/info (requires auth)"
echo "• Admin Service: http://localhost:5002/admin (requires admin role)"
echo "• Security Tests: http://localhost:5003/security-test/start (requires admin role)"
echo ""
echo "🔐 Authentication Flow:"
echo "1. Get token from Keycloak: http://localhost:8080/auth/realms/master/protocol/openid-connect/token"
echo "2. Use token in Authorization header: 'Bearer <token>'"
echo ""

# 11. Monitoring
info "Monitoring URLs:"
echo "• Prometheus: http://localhost:9090"
echo "• Grafana: http://localhost:3000 (admin/admin)"
echo ""

# 12. Logs
info "Viewing logs:"
echo "• All services: docker-compose logs -f"
echo "• Specific service: docker-compose logs -f <service-name>"
echo ""

# 13. Cleanup
info "Cleanup commands:"
echo "• Stop services: docker-compose down"
echo "• Remove volumes: docker-compose down -v"
echo "• Remove everything: docker-compose down -v --remove-orphans"
echo ""

success "Zero Trust Prototype is ready!"
echo ""
echo "🎯 Next Steps:"
echo "1. Configure Keycloak realm and users"
echo "2. Test authentication flows"
echo "3. Run security tests"
echo "4. Review audit logs"
echo "5. Check monitoring dashboards"
echo ""
echo "📚 Documentation: Check README.md for detailed instructions"
