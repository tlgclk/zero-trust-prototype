"""
Security Headers Middleware for Flask Applications
Zero Trust güvenlik header'ları
"""

from flask import Flask, g
from functools import wraps

def add_security_headers(app: Flask):
    """
    Flask uygulamasına güvenlik header'ları ekle
    """
    
    @app.after_request
    def set_security_headers(response):
        # Content Security Policy - XSS koruması
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        
        # X-Content-Type-Options - MIME sniffing koruması
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # X-Frame-Options - Clickjacking koruması
        response.headers['X-Frame-Options'] = 'DENY'
        
        # X-XSS-Protection - XSS koruması (legacy browsers için)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer Policy - Referrer bilgisi kontrolü
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Strict-Transport-Security - HTTPS zorunluluğu
        # Production'da aktif olmalı, development'ta opsiyonel
        if app.config.get('ENV') == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Additional security headers
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    
    return app

def require_secure_headers(f):
    """
    Decorator to ensure endpoint has secure headers
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    
    return decorated_function
