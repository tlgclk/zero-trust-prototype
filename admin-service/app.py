"""
Zero Trust Admin Service
Gelişmiş güvenlik kontrolleri ve audit logging ile
"""

import os
import sys
import json
from flask import Flask, request, jsonify
from datetime import datetime
import logging

# Shared auth utilities import
sys.path.append('/app/shared')
from auth_utils import require_auth, audit_log, get_user_info
from security_headers import add_security_headers

app = Flask(__name__)

# Add security headers to all responses
app = add_security_headers(app)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('admin_service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Health check endpoint
@app.route("/health")
def health_check():
    """Sistem durumu kontrolü"""
    return jsonify({
        "status": "healthy",
        "service": "admin-service",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    })

# Admin dashboard endpoint
@app.route("/admin")
@require_auth(required_roles=['admin'])
@audit_log(action='ACCESS_ADMIN_DASHBOARD', resource='admin_dashboard')
def admin_dashboard():
    """Admin dashboard - sadece admin rolü"""
    user_info = get_user_info()
    
    return jsonify({
        "message": "Welcome to Zero Trust Admin Dashboard!",
        "user": {
            "id": user_info.get('sub'),
            "username": user_info.get('preferred_username'),
            "email": user_info.get('email'),
            "roles": user_info.get('realm_access', {}).get('roles', [])
        },
        "timestamp": datetime.utcnow().isoformat(),
        "capabilities": [
            "user_management",
            "system_monitoring",
            "audit_logs",
            "security_policies"
        ]
    })

# Sistem yapılandırması endpoint
@app.route("/admin/config")
@require_auth(required_roles=['admin'])
@audit_log(action='ACCESS_SYSTEM_CONFIG', resource='system_config')
def system_config():
    """Sistem yapılandırması görüntüleme"""
    return jsonify({
        "config": {
            "security_level": "zero_trust",
            "mfa_enabled": True,
            "session_timeout": 30,
            "password_policy": {
                "min_length": 12,
                "require_special_chars": True,
                "require_uppercase": True,
                "require_numbers": True
            }
        },
        "timestamp": datetime.utcnow().isoformat()
    })

# Audit log görüntüleme endpoint
@app.route("/admin/audit-logs")
@require_auth(required_roles=['admin'])
@audit_log(action='VIEW_AUDIT_LOGS', resource='audit_logs')
def view_audit_logs():
    """Audit logları görüntüleme"""
    try:
        # Son 100 log girişini oku
        logs = []
        if os.path.exists('audit.log'):
            with open('audit.log', 'r') as f:
                lines = f.readlines()
                logs = lines[-100:]  # Son 100 satır
        
        return jsonify({
            "audit_logs": logs,
            "total_entries": len(logs),
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Audit log read error: {str(e)}")
        return jsonify({"error": "Could not retrieve audit logs"}), 500

# Güvenlik politikaları endpoint
@app.route("/admin/security-policies")
@require_auth(required_roles=['admin'])
@audit_log(action='VIEW_SECURITY_POLICIES', resource='security_policies')
def security_policies():
    """Güvenlik politikalarını görüntüleme"""
    return jsonify({
        "policies": {
            "zero_trust": {
                "never_trust_always_verify": True,
                "principle_of_least_privilege": True,
                "verify_explicitly": True
            },
            "network_security": {
                "network_segmentation": True,
                "encrypted_communications": True,
                "network_monitoring": True
            },
            "identity_security": {
                "multi_factor_authentication": True,
                "continuous_identity_verification": True,
                "conditional_access": True
            },
            "device_security": {
                "device_compliance": True,
                "device_health_monitoring": True,
                "device_isolation": True
            }
        },
        "timestamp": datetime.utcnow().isoformat()
    })

# Sistem istatistikleri endpoint
@app.route("/admin/stats")
@require_auth(required_roles=['admin'])
@audit_log(action='VIEW_SYSTEM_STATS', resource='system_stats')
def system_stats():
    """Sistem istatistikleri"""
    return jsonify({
        "stats": {
            "total_users": 50,
            "active_sessions": 12,
            "failed_logins_24h": 3,
            "successful_logins_24h": 45,
            "blocked_ips": 2,
            "security_alerts": 0
        },
        "timestamp": datetime.utcnow().isoformat()
    })

# Error handlers
@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized access"}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Forbidden - Insufficient permissions"}), 403

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({"error": "Rate limit exceeded"}), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500

# Test endpoint for JWT validation
@app.route("/protected")
@require_auth(required_roles=['zero-trust-admin'])
@audit_log(action='ACCESS_PROTECTED', resource='admin_protected_endpoint')
def protected_endpoint():
    """Protected endpoint for JWT validation testing - Admin only"""
    user_info = get_user_info()
    
    return jsonify({
        "message": "Access granted to admin protected resource",
        "user": {
            "id": user_info.get('sub'),
            "username": user_info.get('preferred_username'), 
            "email": user_info.get('email'),
            "roles": user_info.get('realm_access', {}).get('roles', [])
        },
        "admin_access": True,
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == "__main__":
    logger.info("Starting Zero Trust Admin Service")
    app.run(host="0.0.0.0", port=5000, debug=False)
