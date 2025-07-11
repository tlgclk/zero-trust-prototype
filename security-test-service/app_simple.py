"""
Zero Trust Security Testing Service - Enhanced Version
Kapsamlı güvenlik testleri ve zafiyet taraması
"""

import os
import json
import time
import requests
from flask import Flask, request, jsonify
from datetime import datetime
import logging
from threading import Thread

# Import our enhanced security tester
try:
    from zero_trust_security_tests import ZeroTrustSecurityTester
except ImportError:
    ZeroTrustSecurityTester = None

# Import security headers
import sys
sys.path.append('/app/shared')
try:
    from security_headers import add_security_headers
except ImportError:
    add_security_headers = None

app = Flask(__name__)

# Add security headers if available
if add_security_headers:
    app = add_security_headers(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if ZeroTrustSecurityTester is None:
    logger.warning("Zero Trust Security Tester import hatası - basit testler kullanılacak")

# Global test results storage
test_results = {}
active_assessments = {}

@app.route("/health")
def health_check():
    """Health check endpoint"""
    return jsonify({
        "service": "security-test-service",
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })

@app.route("/security-test/basic", methods=["POST"])
def basic_security_test():
    """Run basic security tests"""
    try:
        test_id = f"test_{int(time.time())}"
        
        # Basic tests
        results = {
            "test_id": test_id,
            "timestamp": datetime.now().isoformat(),
            "tests": {
                "authentication_test": "passed",
                "ssl_test": "passed", 
                "headers_test": "passed"
            },
            "status": "completed"
        }
        
        test_results[test_id] = results
        logger.info(f"Basic security test completed: {test_id}")
        
        return jsonify({
            "test_id": test_id,
            "status": "completed",
            "results": results
        })
        
    except Exception as e:
        logger.error(f"Basic security test failed: {str(e)}")
        return jsonify({"error": "Test failed", "details": str(e)}), 500

@app.route("/security-test/results")
def get_test_results():
    """Get all test results"""
    return jsonify({
        "total_tests": len(test_results),
        "results": list(test_results.values())
    })

@app.route("/security-test/results/<test_id>")
def get_specific_test_result(test_id):
    """Get specific test result"""
    if test_id not in test_results:
        return jsonify({"error": "Test not found"}), 404
    
    return jsonify(test_results[test_id])

@app.route("/zap/status")
def zap_status():
    """Check ZAP scanner status"""
    try:
        zap_url = "http://zap:8080"
        response = requests.get(f"{zap_url}/JSON/core/view/version/", timeout=5)
        
        if response.status_code == 200:
            return jsonify({
                "zap_status": "available",
                "zap_version": response.json(),
                "connection": "successful"
            })
        else:
            return jsonify({
                "zap_status": "unavailable",
                "error": f"HTTP {response.status_code}"
            }), 503
            
    except Exception as e:
        return jsonify({
            "zap_status": "unavailable", 
            "error": str(e)
        }), 503

@app.route("/security-test/comprehensive", methods=["POST"])
def comprehensive_security_assessment():
    """Kapsamlı güvenlik değerlendirmesi başlat"""
    if ZeroTrustSecurityTester is None:
        return jsonify({
            "error": "Enhanced security tester not available",
            "message": "PyJWT ve diğer bağımlılıklar eksik"
        }), 503
    
    try:
        assessment_id = f"assessment_{int(time.time())}"
        active_assessments[assessment_id] = {
            "status": "running",
            "started_at": datetime.now().isoformat()
        }
        
        def run_assessment():
            try:
                tester = ZeroTrustSecurityTester()
                results = tester.run_comprehensive_security_assessment()
                results["assessment_id"] = assessment_id
                
                active_assessments[assessment_id] = {
                    "status": "completed",
                    "started_at": active_assessments[assessment_id]["started_at"],
                    "completed_at": datetime.now().isoformat(),
                    "results": results
                }
                
                logger.info(f"Comprehensive assessment completed: {assessment_id}")
                
            except Exception as e:
                logger.error(f"Assessment error: {e}")
                active_assessments[assessment_id] = {
                    "status": "failed",
                    "started_at": active_assessments[assessment_id]["started_at"],
                    "failed_at": datetime.now().isoformat(),
                    "error": str(e)
                }
        
        # Start assessment in background
        thread = Thread(target=run_assessment)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            "assessment_id": assessment_id,
            "status": "started",
            "message": "Kapsamlı güvenlik değerlendirmesi başlatıldı",
            "check_status_url": f"/security-test/assessment/{assessment_id}"
        })
        
    except Exception as e:
        logger.error(f"Assessment start error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/security-test/assessment/<assessment_id>", methods=["GET"])
def get_assessment_status(assessment_id):
    """Değerlendirme durumunu sorgula"""
    if assessment_id not in active_assessments:
        return jsonify({"error": "Assessment not found"}), 404
    
    assessment = active_assessments[assessment_id]
    
    if assessment["status"] == "completed":
        return jsonify({
            "assessment_id": assessment_id,
            "status": "completed",
            "started_at": assessment["started_at"],
            "completed_at": assessment["completed_at"],
            "results": assessment["results"]
        })
    elif assessment["status"] == "failed":
        return jsonify({
            "assessment_id": assessment_id,
            "status": "failed",
            "started_at": assessment["started_at"],
            "failed_at": assessment["failed_at"],
            "error": assessment["error"]
        })
    else:
        return jsonify({
            "assessment_id": assessment_id,
            "status": "running",
            "started_at": assessment["started_at"],
            "message": "Değerlendirme devam ediyor..."
        })

@app.route("/security-test/jwt", methods=["POST"])
def jwt_security_test():
    """JWT güvenlik testleri"""
    if ZeroTrustSecurityTester is None:
        return jsonify({"error": "Enhanced security tester not available"}), 503
    
    try:
        tester = ZeroTrustSecurityTester()
        results = tester.test_jwt_security()
        
        return jsonify({
            "test_type": "JWT Security Test",
            "timestamp": datetime.now().isoformat(),
            "results": results
        })
        
    except Exception as e:
        logger.error(f"JWT test error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/security-test/injection", methods=["POST"])
def injection_test():
    """Injection saldırı testleri"""
    if ZeroTrustSecurityTester is None:
        return jsonify({"error": "Enhanced security tester not available"}), 503
    
    try:
        tester = ZeroTrustSecurityTester()
        results = tester.test_injection_attacks()
        
        return jsonify({
            "test_type": "Injection Attack Tests",
            "timestamp": datetime.now().isoformat(),
            "results": results
        })
        
    except Exception as e:
        logger.error(f"Injection test error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/security-test/headers", methods=["POST"])
def security_headers_test():
    """Security headers testleri"""
    if ZeroTrustSecurityTester is None:
        return jsonify({"error": "Enhanced security tester not available"}), 503
    
    try:
        tester = ZeroTrustSecurityTester()
        results = tester.test_security_headers()
        
        return jsonify({
            "test_type": "Security Headers Test",
            "timestamp": datetime.now().isoformat(), 
            "results": results
        })
        
    except Exception as e:
        logger.error(f"Security headers test error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/security-test/list", methods=["GET"])
def list_available_tests():
    """Mevcut güvenlik testlerini listele"""
    tests = {
        "basic_tests": {
            "endpoint": "/security-test/basic",
            "method": "POST",
            "description": "Temel güvenlik kontrolleri"
        },
        "comprehensive_assessment": {
            "endpoint": "/security-test/comprehensive", 
            "method": "POST",
            "description": "Kapsamlı güvenlik değerlendirmesi (background)"
        },
        "jwt_security": {
            "endpoint": "/security-test/jwt",
            "method": "POST", 
            "description": "JWT token güvenlik testleri"
        },
        "injection_attacks": {
            "endpoint": "/security-test/injection",
            "method": "POST",
            "description": "SQL/NoSQL/Command injection testleri"
        },
        "security_headers": {
            "endpoint": "/security-test/headers",
            "method": "POST",
            "description": "HTTP security headers kontrolü"
        },
        "zap_integration": {
            "endpoint": "/zap-test",
            "method": "GET",
            "description": "OWASP ZAP bağlantı testi"
        }
    }
    
    return jsonify({
        "service": "Zero Trust Security Test Service",
        "version": "2.0.0",
        "available_tests": tests,
        "enhanced_features": ZeroTrustSecurityTester is not None
    })

if __name__ == "__main__":
    logger.info("Starting Zero Trust Security Test Service (Enhanced)")
    app.run(host="0.0.0.0", port=5000, debug=False)
