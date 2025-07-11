"""
Zero Trust API Security Testing Suite
Kapsamlı API güvenlik testleri ve vulnerability assessment
"""

import os
import json
import time
import requests
import hashlib
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging
from concurrent.futures import ThreadPoolExecutor
import re
import base64
import jwt
from urllib.parse import urlencode

# Logging konfigürasyonu
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ZeroTrustSecurityTester:
    def __init__(self):
        # Zero Trust konfigürasyonu
        self.keycloak_url = os.getenv('KEYCLOAK_URL', 'http://keycloak:8080')
        self.keycloak_realm = os.getenv('KEYCLOAK_REALM', 'zero-trust')
        self.client_id = os.getenv('KEYCLOAK_CLIENT_ID', 'zero-trust-client')
        self.client_secret = os.getenv('KEYCLOAK_CLIENT_SECRET', 'zero-trust-secret-2024')
        
        # Test servisleri
        self.services = {
            "user-service": "http://user-service:5000",
            "admin-service": "http://admin-service:5000", 
            "security-test-service": "http://security-test-service:5000",
            "keycloak": self.keycloak_url,
            "nginx": "http://nginx:80"
        }
        
        # ZAP konfigürasyonu
        self.zap_proxy = os.getenv('ZAP_PROXY_URL', 'http://zap:8080')
        self.zap_api_key = os.getenv('ZAP_API_KEY', 'zero-trust-api-key')
        
        # Test sonuçları
        self.test_results = {}
        self.access_token = None
        
    def get_access_token(self, username="testuser", password="testpass123") -> str:
        """Keycloak'tan access token al"""
        token_url = f"{self.keycloak_url}/realms/{self.keycloak_realm}/protocol/openid-connect/token"
        
        data = {
            'username': username,
            'password': password,
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        try:
            response = requests.post(token_url, data=data, timeout=10)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data['access_token']
            logger.info("✅ Access token başarıyla alındı")
            return self.access_token
        except Exception as e:
            logger.error(f"❌ Token alma hatası: {e}")
            return None
    
    def test_jwt_security(self) -> Dict:
        """JWT token güvenlik testleri"""
        results = {
            "test_name": "JWT Security Tests",
            "timestamp": datetime.utcnow().isoformat(),
            "tests": []
        }
        
        logger.info("🔐 JWT güvenlik testleri başlatılıyor...")
        
        # Token al
        token = self.get_access_token()
        if not token:
            results["tests"].append({
                "name": "JWT Token Acquisition",
                "status": "FAILED",
                "message": "Token alınamadı"
            })
            return results
        
        # 1. JWT Header analizi
        try:
            header = jwt.get_unverified_header(token)
            results["tests"].append({
                "name": "JWT Header Analysis",
                "status": "PASSED",
                "details": {
                    "algorithm": header.get('alg'),
                    "type": header.get('typ'),
                    "key_id": header.get('kid', 'Not present')
                },
                "security_note": "RS256 kullanılıyor mu?" if header.get('alg') == 'RS256' else "Güvensiz algoritma!"
            })
        except Exception as e:
            results["tests"].append({
                "name": "JWT Header Analysis", 
                "status": "FAILED",
                "message": str(e)
            })
        
        # 2. JWT Payload analizi
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp_time = datetime.fromtimestamp(payload.get('exp', 0))
            current_time = datetime.utcnow()
            
            results["tests"].append({
                "name": "JWT Payload Analysis",
                "status": "PASSED",
                "details": {
                    "issuer": payload.get('iss'),
                    "audience": payload.get('aud'),
                    "subject": payload.get('sub'),
                    "expiration": exp_time.isoformat(),
                    "issued_at": datetime.fromtimestamp(payload.get('iat', 0)).isoformat(),
                    "time_until_expiry": str(exp_time - current_time),
                    "roles": payload.get('realm_access', {}).get('roles', [])
                }
            })
        except Exception as e:
            results["tests"].append({
                "name": "JWT Payload Analysis",
                "status": "FAILED", 
                "message": str(e)
            })
        
        # 3. Token manipulation test
        try:
            # Token'ı manipüle et
            parts = token.split('.')
            manipulated_payload = base64.b64encode(
                '{"sub":"hacker","exp":9999999999}'.encode()
            ).decode().rstrip('=')
            manipulated_token = f"{parts[0]}.{manipulated_payload}.{parts[2]}"
            
            # Manipüle edilmiş token ile test
            headers = {'Authorization': f'Bearer {manipulated_token}'}
            response = requests.get(f"{self.services['user-service']}/protected", headers=headers)
            
            if response.status_code == 401:
                results["tests"].append({
                    "name": "JWT Manipulation Protection",
                    "status": "PASSED",
                    "message": "Manipüle edilmiş token reddedildi"
                })
            else:
                results["tests"].append({
                    "name": "JWT Manipulation Protection",
                    "status": "FAILED",
                    "message": f"Manipüle edilmiş token kabul edildi! Status: {response.status_code}",
                    "severity": "HIGH"
                })
        except Exception as e:
            results["tests"].append({
                "name": "JWT Manipulation Protection",
                "status": "ERROR",
                "message": str(e)
            })
        
        return results
    
    def test_authentication_bypass(self) -> Dict:
        """Authentication bypass testleri"""
        results = {
            "test_name": "Authentication Bypass Tests",
            "timestamp": datetime.utcnow().isoformat(),
            "tests": []
        }
        
        logger.info("🔓 Authentication bypass testleri başlatılıyor...")
        
        # Test endpoint'leri
        protected_endpoints = [
            "/protected",
            "/admin",
            "/users",
            "/config"
        ]
        
        bypass_payloads = [
            None,  # No auth header
            "Bearer invalid_token",
            "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJoYWNrZXIifQ.",  # None algorithm
            "Basic YWRtaW46YWRtaW4=",  # Basic auth
            "Bearer " + "A" * 500,  # Long token
        ]
        
        for service_name, service_url in self.services.items():
            if service_name in ['keycloak', 'nginx']:
                continue
                
            for endpoint in protected_endpoints:
                for i, payload in enumerate(bypass_payloads):
                    try:
                        headers = {}
                        if payload:
                            headers['Authorization'] = payload
                        
                        response = requests.get(
                            f"{service_url}{endpoint}",
                            headers=headers,
                            timeout=5
                        )
                        
                        test_name = f"{service_name}{endpoint} - Bypass Test #{i+1}"
                        
                        if response.status_code in [401, 403]:
                            results["tests"].append({
                                "name": test_name,
                                "status": "PASSED",
                                "message": f"Unauthorized access correctly blocked (HTTP {response.status_code})"
                            })
                        elif response.status_code == 404:
                            results["tests"].append({
                                "name": test_name,
                                "status": "INFO",
                                "message": "Endpoint not found"
                            })
                        else:
                            results["tests"].append({
                                "name": test_name,
                                "status": "FAILED",
                                "message": f"Potential bypass! HTTP {response.status_code}",
                                "severity": "HIGH",
                                "payload": payload[:50] if payload else "No auth"
                            })
                    except requests.exceptions.RequestException as e:
                        results["tests"].append({
                            "name": f"{service_name}{endpoint} - Bypass Test #{i+1}",
                            "status": "ERROR",
                            "message": f"Connection error: {str(e)[:100]}"
                        })
        
        return results
    
    def test_injection_attacks(self) -> Dict:
        """SQL/NoSQL/Command injection testleri"""
        results = {
            "test_name": "Injection Attack Tests", 
            "timestamp": datetime.utcnow().isoformat(),
            "tests": []
        }
        
        logger.info("💉 Injection attack testleri başlatılıyor...")
        
        # Injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "' OR 1=1#"
        ]
        
        nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$where": "function() { return true; }"}',
            '{"$regex": ".*"}'
        ]
        
        command_payloads = [
            "; cat /etc/passwd",
            "| whoami",
            "& dir",
            "`id`",
            "$(ls -la)"
        ]
        
        # Test endpoints
        test_endpoints = [
            ("/login", {"username": "PAYLOAD", "password": "test"}),
            ("/search", {"q": "PAYLOAD"}),
            ("/user", {"id": "PAYLOAD"}),
            ("/config", {"setting": "PAYLOAD"})
        ]
        
        token = self.get_access_token()
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        all_payloads = [
            ("SQL", sql_payloads),
            ("NoSQL", nosql_payloads), 
            ("Command", command_payloads)
        ]
        
        for service_name, service_url in self.services.items():
            if service_name in ['keycloak', 'nginx']:
                continue
                
            for endpoint, params in test_endpoints:
                for payload_type, payloads in all_payloads:
                    for payload in payloads:
                        try:
                            # Payload'ı parametreye yerleştir
                            test_params = {}
                            for key, value in params.items():
                                test_params[key] = value.replace("PAYLOAD", payload)
                            
                            # POST isteği gönder
                            response = requests.post(
                                f"{service_url}{endpoint}",
                                json=test_params,
                                headers=headers,
                                timeout=5
                            )
                            
                            test_name = f"{service_name}{endpoint} - {payload_type} Injection"
                            
                            # Hata mesajlarında injection belirtisi ara
                            response_text = response.text.lower()
                            error_indicators = [
                                'sql', 'mysql', 'postgresql', 'sqlite',
                                'syntax error', 'database', 'query',
                                'mongodb', 'nosql',
                                'command not found', 'permission denied',
                                'syntax error near', 'error in your sql'
                            ]
                            
                            if any(indicator in response_text for indicator in error_indicators):
                                results["tests"].append({
                                    "name": test_name,
                                    "status": "FAILED",
                                    "message": f"Potential {payload_type} injection vulnerability detected",
                                    "severity": "HIGH",
                                    "payload": payload,
                                    "response_status": response.status_code,
                                    "error_snippet": response_text[:200]
                                })
                            elif response.status_code >= 500:
                                results["tests"].append({
                                    "name": test_name,
                                    "status": "WARNING",
                                    "message": f"Server error with injection payload (HTTP {response.status_code})",
                                    "payload": payload
                                })
                            else:
                                results["tests"].append({
                                    "name": test_name,
                                    "status": "PASSED",
                                    "message": "No injection vulnerability detected"
                                })
                                
                        except requests.exceptions.RequestException as e:
                            results["tests"].append({
                                "name": f"{service_name}{endpoint} - {payload_type} Injection",
                                "status": "ERROR",
                                "message": f"Connection error: {str(e)[:100]}"
                            })
        
        return results
    
    def test_xss_attacks(self) -> Dict:
        """Cross-Site Scripting (XSS) testleri"""
        results = {
            "test_name": "XSS Attack Tests",
            "timestamp": datetime.utcnow().isoformat(), 
            "tests": []
        }
        
        logger.info("🌐 XSS attack testleri başlatılıyor...")
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        # Test parametreleri
        test_params = [
            ("name", "PAYLOAD"),
            ("comment", "PAYLOAD"),
            ("search", "PAYLOAD"),
            ("title", "PAYLOAD"),
            ("description", "PAYLOAD")
        ]
        
        token = self.get_access_token()
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        for service_name, service_url in self.services.items():
            if service_name in ['keycloak']:
                continue
                
            for param_name, param_template in test_params:
                for payload in xss_payloads:
                    try:
                        test_data = {param_name: param_template.replace("PAYLOAD", payload)}
                        
                        # POST isteği
                        response = requests.post(
                            f"{service_url}/test",
                            json=test_data,
                            headers=headers,
                            timeout=5
                        )
                        
                        test_name = f"{service_name} - XSS in {param_name}"
                        
                        # Response'da payload'ın reflected olup olmadığını kontrol et
                        if payload in response.text:
                            # HTML encoding kontrolü
                            encoded_chars = ['&lt;', '&gt;', '&amp;', '&quot;', '&#x27;']
                            if any(char in response.text for char in encoded_chars):
                                results["tests"].append({
                                    "name": test_name,
                                    "status": "PASSED",
                                    "message": "XSS payload properly encoded"
                                })
                            else:
                                results["tests"].append({
                                    "name": test_name,
                                    "status": "FAILED",
                                    "message": "Potential reflected XSS vulnerability",
                                    "severity": "MEDIUM",
                                    "payload": payload
                                })
                        else:
                            results["tests"].append({
                                "name": test_name,
                                "status": "PASSED",
                                "message": "XSS payload not reflected"
                            })
                            
                    except requests.exceptions.RequestException as e:
                        results["tests"].append({
                            "name": f"{service_name} - XSS in {param_name}",
                            "status": "ERROR",
                            "message": f"Connection error: {str(e)[:100]}"
                        })
        
        return results
    
    def test_security_headers(self) -> Dict:
        """Security headers testleri"""
        results = {
            "test_name": "Security Headers Tests",
            "timestamp": datetime.utcnow().isoformat(),
            "tests": []
        }
        
        logger.info("🛡️ Security headers testleri başlatılıyor...")
        
        # Önemli security headers
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1; mode=block', 
            'Strict-Transport-Security': None,  # HTTPS için
            'Content-Security-Policy': None,
            'Referrer-Policy': None,
            'Permissions-Policy': None
        }
        
        for service_name, service_url in self.services.items():
            try:
                response = requests.get(service_url, timeout=5)
                service_results = {
                    "service": service_name,
                    "url": service_url,
                    "headers_present": {},
                    "headers_missing": [],
                    "security_score": 0
                }
                
                headers = response.headers
                total_headers = len(required_headers)
                present_headers = 0
                
                for header_name, expected_value in required_headers.items():
                    if header_name in headers:
                        header_value = headers[header_name]
                        service_results["headers_present"][header_name] = header_value
                        
                        if expected_value:
                            if isinstance(expected_value, list):
                                if any(val in header_value for val in expected_value):
                                    present_headers += 1
                            elif expected_value in header_value:
                                present_headers += 1
                        else:
                            present_headers += 1
                    else:
                        service_results["headers_missing"].append(header_name)
                
                service_results["security_score"] = round((present_headers / total_headers) * 100)
                
                # Overall assessment
                if service_results["security_score"] >= 80:
                    status = "PASSED"
                    message = f"Good security headers coverage ({service_results['security_score']}%)"
                elif service_results["security_score"] >= 50:
                    status = "WARNING"
                    message = f"Moderate security headers coverage ({service_results['security_score']}%)"
                else:
                    status = "FAILED"
                    message = f"Poor security headers coverage ({service_results['security_score']}%)"
                
                results["tests"].append({
                    "name": f"{service_name} - Security Headers",
                    "status": status,
                    "message": message,
                    "details": service_results
                })
                
            except requests.exceptions.RequestException as e:
                results["tests"].append({
                    "name": f"{service_name} - Security Headers",
                    "status": "ERROR",
                    "message": f"Connection error: {str(e)[:100]}"
                })
        
        return results
    
    def run_comprehensive_security_assessment(self) -> Dict:
        """Kapsamlı güvenlik değerlendirmesi"""
        logger.info("🚀 Kapsamlı API güvenlik değerlendirmesi başlatılıyor...")
        
        assessment_results = {
            "assessment_id": hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()[:8],
            "timestamp": datetime.utcnow().isoformat(),
            "zero_trust_config": {
                "keycloak_realm": self.keycloak_realm,
                "client_id": self.client_id,
                "services_tested": list(self.services.keys())
            },
            "test_categories": {}
        }
        
        # Test kategorileri
        test_categories = [
            ("jwt_security", self.test_jwt_security),
            ("authentication_bypass", self.test_authentication_bypass), 
            ("injection_attacks", self.test_injection_attacks),
            ("xss_attacks", self.test_xss_attacks),
            ("security_headers", self.test_security_headers)
        ]
        
        # Testleri sırayla çalıştır
        for category_name, test_function in test_categories:
            try:
                logger.info(f"🔍 {category_name} testleri çalıştırılıyor...")
                category_results = test_function()
                assessment_results["test_categories"][category_name] = category_results
                
                # Test sonuçlarını özetle
                passed = len([t for t in category_results["tests"] if t["status"] == "PASSED"])
                failed = len([t for t in category_results["tests"] if t["status"] == "FAILED"])
                warnings = len([t for t in category_results["tests"] if t["status"] == "WARNING"])
                errors = len([t for t in category_results["tests"] if t["status"] == "ERROR"])
                
                logger.info(f"✅ {category_name}: {passed} passed, {failed} failed, {warnings} warnings, {errors} errors")
                
            except Exception as e:
                logger.error(f"❌ {category_name} testlerinde hata: {e}")
                assessment_results["test_categories"][category_name] = {
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                }
        
        # Genel özet
        self._generate_assessment_summary(assessment_results)
        
        return assessment_results
    
    def _generate_assessment_summary(self, results: Dict):
        """Değerlendirme özeti oluştur"""
        summary = {
            "total_tests": 0,
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "errors": 0,
            "high_severity_issues": 0,
            "security_score": 0
        }
        
        for category_name, category_data in results["test_categories"].items():
            if "tests" in category_data:
                for test in category_data["tests"]:
                    summary["total_tests"] += 1
                    status = test["status"]
                    
                    if status == "PASSED":
                        summary["passed"] += 1
                    elif status == "FAILED":
                        summary["failed"] += 1
                        if test.get("severity") == "HIGH":
                            summary["high_severity_issues"] += 1
                    elif status == "WARNING":
                        summary["warnings"] += 1
                    elif status == "ERROR":
                        summary["errors"] += 1
        
        # Güvenlik skoru hesapla
        if summary["total_tests"] > 0:
            summary["security_score"] = round((summary["passed"] / summary["total_tests"]) * 100)
        
        results["summary"] = summary
        
        # Log özet
        logger.info(f"""
📊 GÜVENLIK DEĞERLENDİRME ÖZETİ:
   📋 Toplam Test: {summary['total_tests']}
   ✅ Başarılı: {summary['passed']}
   ❌ Başarısız: {summary['failed']}
   ⚠️ Uyarı: {summary['warnings']}
   🔥 Yüksek Risk: {summary['high_severity_issues']}
   📈 Güvenlik Skoru: {summary['security_score']}%
        """)

def main():
    """Ana test fonksiyonu"""
    tester = ZeroTrustSecurityTester()
    
    # Kapsamlı güvenlik değerlendirmesi çalıştır
    results = tester.run_comprehensive_security_assessment()
    
    # Sonuçları JSON dosyasına kaydet
    output_file = f"/tmp/security_assessment_{results['assessment_id']}.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"📄 Sonuçlar kaydedildi: {output_file}")
    except Exception as e:
        logger.error(f"❌ Sonuç kaydetme hatası: {e}")
    
    return results

if __name__ == "__main__":
    main()
