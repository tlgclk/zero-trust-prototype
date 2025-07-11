"""
Zero Trust User Service
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
        logging.FileHandler('user_service.log'),
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
        "service": "user-service",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    })

# User info endpoint
@app.route("/info")
@require_auth(required_roles=['user', 'admin'])
@audit_log(action='ACCESS_USER_INFO', resource='user_info')
def user_info():
    """Kullanıcı bilgileri - user ve admin rolleri"""
    user_info = get_user_info()
    
    return jsonify({
        "message": "Welcome to Zero Trust User Service!",
        "user": {
            "id": user_info.get('sub'),
            "username": user_info.get('preferred_username'),
            "email": user_info.get('email'),
            "roles": user_info.get('realm_access', {}).get('roles', []),
            "first_name": user_info.get('given_name'),
            "last_name": user_info.get('family_name')
        },
        "timestamp": datetime.utcnow().isoformat(),
        "session_info": {
            "token_issued_at": datetime.fromtimestamp(user_info.get('iat', 0)).isoformat(),
            "token_expires_at": datetime.fromtimestamp(user_info.get('exp', 0)).isoformat(),
            "session_state": user_info.get('session_state')
        }
    })

# Kullanıcı profili endpoint
@app.route("/profile")
@require_auth(required_roles=['user', 'admin'])
@audit_log(action='VIEW_USER_PROFILE', resource='user_profile')
def user_profile():
    """Kullanıcı profili görüntüleme"""
    user_info = get_user_info()
    
    return jsonify({
        "profile": {
            "user_id": user_info.get('sub'),
            "username": user_info.get('preferred_username'),
            "email": user_info.get('email'),
            "first_name": user_info.get('given_name'),
            "last_name": user_info.get('family_name'),
            "email_verified": user_info.get('email_verified'),
            "roles": user_info.get('realm_access', {}).get('roles', [])
        },
        "preferences": {
            "language": "tr_TR",
            "timezone": "Europe/Istanbul",
            "notifications": True
        },
        "timestamp": datetime.utcnow().isoformat()
    })

# Kullanıcı aktivitesi endpoint
@app.route("/activity")
@require_auth(required_roles=['user', 'admin'])
@audit_log(action='VIEW_USER_ACTIVITY', resource='user_activity')
def user_activity():
    """Kullanıcı aktivite geçmişi"""
    user_info = get_user_info()
    
    # Simulated activity data
    activities = [
        {
            "timestamp": datetime.utcnow().isoformat(),
            "action": "LOGIN",
            "resource": "user_service",
            "ip_address": request.remote_addr,
            "status": "SUCCESS"
        },
        {
            "timestamp": (datetime.utcnow()).isoformat(),
            "action": "VIEW_PROFILE",
            "resource": "user_profile",
            "ip_address": request.remote_addr,
            "status": "SUCCESS"
        }
    ]
    
    return jsonify({
        "user_id": user_info.get('sub'),
        "activities": activities,
        "total_activities": len(activities),
        "timestamp": datetime.utcnow().isoformat()
    })

# Güvenlik durumu endpoint
@app.route("/security-status")
@require_auth(required_roles=['user', 'admin'])
@audit_log(action='VIEW_SECURITY_STATUS', resource='security_status')
def security_status():
    """Kullanıcı güvenlik durumu"""
    user_info = get_user_info()
    
    return jsonify({
        "security_status": {
            "mfa_enabled": True,
            "password_strength": "strong",
            "last_password_change": "2024-01-15",
            "suspicious_activity": False,
            "account_locked": False,
            "login_attempts_today": 1
        },
        "recommendations": [
            "Enable two-factor authentication",
            "Update password regularly",
            "Review account activity"
        ],
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
@require_auth(required_roles=['zero-trust-user', 'zero-trust-admin'])
@audit_log(action='ACCESS_PROTECTED', resource='protected_endpoint')
def protected_endpoint():
    """Protected endpoint for JWT validation testing"""
    user_info = get_user_info()
    
    return jsonify({
        "message": "Access granted to protected resource",
        "user": {
            "id": user_info.get('sub'),
            "username": user_info.get('preferred_username'),
            "email": user_info.get('email'),
            "roles": user_info.get('realm_access', {}).get('roles', [])
        },
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == "__main__":
    logger.info("Starting Zero Trust User Service")
    app.run(host="0.0.0.0", port=5000, debug=False)
