# API Documentation - Zero Trust Prototype

## Overview

Bu dokümantasyon Zero Trust prototype projesinin API endpoint'lerini ve kullanım örneklerini içermektedir.

## Authentication

Tüm protected endpoint'ler JWT Bearer token gerektirir.

### Token Alma

```bash
curl -X POST http://localhost:8080/realms/zero-trust/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=zero-trust-client" \
  -d "username=testuser" \
  -d "password=testpass123"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "scope": "profile email"
}
```

## User Service API (Port 5001)

### Health Check
- **Method**: GET
- **URL**: `/health`
- **Auth**: No
- **Description**: Service sağlık durumu kontrolü

**Request:**
```bash
curl http://localhost:5001/health
```

**Response:**
```json
{
  "service": "user-service",
  "status": "healthy",
  "timestamp": "2025-07-11T08:55:00.123456",
  "version": "1.0.0"
}
```

### Protected User Info
- **Method**: GET
- **URL**: `/protected`
- **Auth**: Bearer Token Required
- **Description**: JWT token ile korunmuş endpoint

**Request:**
```bash
curl -H "Authorization: Bearer {JWT_TOKEN}" \
     http://localhost:5001/protected
```

**Response:**
```json
{
  "message": "Bu korunmuş bir endpoint'tir",
  "user": {
    "username": "testuser",
    "roles": ["zero-trust-user"],
    "email": "testuser@zerotrust.local"
  },
  "timestamp": "2025-07-11T08:55:00.123456"
}
```

## Admin Service API (Port 5002)

### Health Check
- **Method**: GET
- **URL**: `/health`
- **Auth**: No
- **Description**: Service sağlık durumu kontrolü

**Request:**
```bash
curl http://localhost:5002/health
```

**Response:**
```json
{
  "service": "admin-service",
  "status": "healthy",
  "timestamp": "2025-07-11T08:55:00.123456",
  "version": "1.0.0"
}
```

### Protected Admin Area
- **Method**: GET
- **URL**: `/protected`
- **Auth**: Bearer Token Required
- **Description**: JWT token ile korunmuş admin endpoint

**Request:**
```bash
curl -H "Authorization: Bearer {JWT_TOKEN}" \
     http://localhost:5002/protected
```

**Response:**
```json
{
  "message": "Admin korunmuş endpoint'ine erişim başarılı",
  "user": {
    "username": "testuser",
    "roles": ["zero-trust-user"],
    "email": "testuser@zerotrust.local"
  },
  "admin_access": true,
  "timestamp": "2025-07-11T08:55:00.123456"
}
```

## Security Test Service API (Port 5003)

### Health Check
- **Method**: GET
- **URL**: `/health`
- **Auth**: No
- **Description**: Service sağlık durumu kontrolü

**Request:**
```bash
curl http://localhost:5003/health
```

**Response:**
```json
{
  "service": "security-test-service",
  "status": "healthy",
  "timestamp": "2025-07-11T08:55:00.123456",
  "version": "1.0.0"
}
```

### Basic Security Test
- **Method**: POST
- **URL**: `/security-test/basic`
- **Auth**: No
- **Description**: Temel güvenlik testlerini çalıştırır

**Request:**
```bash
curl -X POST -H "Content-Type: application/json" \
     http://localhost:5003/security-test/basic
```

**Response:**
```json
{
  "test_id": "test_1752224168",
  "status": "completed",
  "results": {
    "test_id": "test_1752224168",
    "timestamp": "2025-07-11T08:56:08.831952",
    "tests": {
      "authentication_test": "passed",
      "ssl_test": "passed",
      "headers_test": "passed"
    },
    "status": "completed"
  }
}
```

### Comprehensive Security Assessment
- **Method**: POST
- **URL**: `/security-test/comprehensive`
- **Auth**: No
- **Description**: Kapsamlı güvenlik değerlendirmesi başlatır

**Request:**
```bash
curl -X POST -H "Content-Type: application/json" \
     http://localhost:5003/security-test/comprehensive
```

**Response:**
```json
{
  "assessment_id": "assessment_1752224077",
  "status": "started",
  "message": "Kapsamlı güvenlik değerlendirmesi başlatıldı",
  "check_status_url": "/security-test/assessment/assessment_1752224077"
}
```

### Assessment Status Check
- **Method**: GET
- **URL**: `/security-test/assessment/{assessment_id}`
- **Auth**: No
- **Description**: Assessment durumu kontrolü

**Request:**
```bash
curl http://localhost:5003/security-test/assessment/assessment_1752224077
```

**Response (Running):**
```json
{
  "assessment_id": "assessment_1752224077",
  "status": "running",
  "message": "Değerlendirme devam ediyor...",
  "started_at": "2025-07-11T08:54:37.576113"
}
```

**Response (Completed):**
```json
{
  "assessment_id": "assessment_1752224077",
  "status": "completed",
  "started_at": "2025-07-11T08:54:37.576113",
  "completed_at": "2025-07-11T08:56:15.234567",
  "results": {
    "jwt_tests": {
      "signature_validation": "passed",
      "token_manipulation": "passed",
      "expiration_check": "passed"
    },
    "injection_tests": {
      "sql_injection": "passed",
      "command_injection": "passed"
    },
    "security_headers": {
      "hsts": "passed",
      "csp": "passed",
      "x_frame_options": "passed"
    },
    "overall_score": "95/100"
  }
}
```

### Get All Test Results
- **Method**: GET
- **URL**: `/security-test/results`
- **Auth**: No
- **Description**: Tüm test sonuçlarını getirir

**Request:**
```bash
curl http://localhost:5003/security-test/results
```

**Response:**
```json
{
  "total_tests": 2,
  "results": [
    {
      "test_id": "test_1752224168",
      "timestamp": "2025-07-11T08:56:08.831952",
      "status": "completed",
      "tests": {
        "authentication_test": "passed",
        "ssl_test": "passed", 
        "headers_test": "passed"
      }
    }
  ]
}
```

### ZAP Scanner Status
- **Method**: GET
- **URL**: `/zap/status`
- **Auth**: No
- **Description**: OWASP ZAP scanner durumu

**Request:**
```bash
curl http://localhost:5003/zap/status
```

**Response:**
```json
{
  "zap_status": "available",
  "zap_version": {
    "version": "2.14.0"
  },
  "connection": "successful"
}
```

## Error Responses

### 401 Unauthorized
JWT token geçersiz veya eksik olduğunda:

```json
{
  "error": "Unauthorized - Invalid token"
}
```

### 403 Forbidden
Yeterli yetki olmadığında:

```json
{
  "error": "Forbidden - Insufficient privileges"
}
```

### 404 Not Found
Endpoint bulunamadığında:

```json
{
  "error": "Endpoint not found"
}
```

### 500 Internal Server Error
Sunucu hatası durumunda:

```json
{
  "error": "Internal server error",
  "details": "Error details here"
}
```

## Security Headers

Tüm response'larda aşağıdaki güvenlik başlıkları bulunur:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## Rate Limiting

API'ler rate limiting uygulamaktadır:
- **Limit**: 100 request/minute per IP
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`

## Postman Collection

Postman collection dosyası proje kök dizininde `postman_collection.json` olarak bulunmaktadır.

## Testing Examples

### Complete Authentication Flow

```bash
#!/bin/bash

# 1. Token al
TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/realms/zero-trust/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=zero-trust-client" \
  -d "username=testuser" \
  -d "password=testpass123")

# 2. Token extract et
TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

# 3. Protected endpoint'e erişim
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5001/protected

# 4. Admin endpoint'e erişim
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:5002/protected
```

### Security Test Flow

```bash
#!/bin/bash

# 1. Basic security test
BASIC_TEST=$(curl -s -X POST -H "Content-Type: application/json" \
             http://localhost:5003/security-test/basic)

echo "Basic Test Result: $BASIC_TEST"

# 2. Comprehensive assessment
ASSESSMENT=$(curl -s -X POST -H "Content-Type: application/json" \
             http://localhost:5003/security-test/comprehensive)

ASSESSMENT_ID=$(echo $ASSESSMENT | jq -r '.assessment_id')

# 3. Assessment durumunu kontrol et
sleep 30
RESULT=$(curl -s http://localhost:5003/security-test/assessment/$ASSESSMENT_ID)

echo "Assessment Result: $RESULT"
```
