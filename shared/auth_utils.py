"""
Zero Trust Authentication Utilities
Keycloak entegrasyonu için güvenli JWT doğrulama
"""

import os
import json
import time
import logging
from typing import Dict, Optional, List
import requests
import jwt
from jwt.exceptions import InvalidTokenError
from flask import request, jsonify
from functools import wraps
from datetime import datetime, timedelta
import hashlib
from cryptography.hazmat.primitives import serialization

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class KeycloakAuth:
    def __init__(self, keycloak_url: str, realm: str, client_id: str):
        self.keycloak_url = keycloak_url
        self.realm = realm
        self.client_id = client_id
        self.jwks_cache = {}
        self.jwks_cache_time = 0
        self.cache_ttl = 3600  # 1 hour
        
    def get_jwks(self) -> Dict:
        """Keycloak'tan JWKS (JSON Web Key Set) al ve önbelleğe al"""
        current_time = time.time()
        
        if (current_time - self.jwks_cache_time) < self.cache_ttl and self.jwks_cache:
            return self.jwks_cache
            
        try:
            jwks_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/certs"
            response = requests.get(jwks_url, timeout=10)
            response.raise_for_status()
            
            self.jwks_cache = response.json()
            self.jwks_cache_time = current_time
            
            logger.info(f"JWKS updated from {jwks_url}")
            return self.jwks_cache
            
        except Exception as e:
            logger.error(f"JWKS fetch failed: {str(e)}")
            if self.jwks_cache:
                return self.jwks_cache
            raise Exception("Could not fetch JWKS")
    
    def jwk_to_rsa_key(self, jwk_key):
        """Convert JWK to RSA public key for PyJWT"""
        import base64
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        
        # Decode n and e from base64url
        n = base64.urlsafe_b64decode(jwk_key['n'] + '==')
        e = base64.urlsafe_b64decode(jwk_key['e'] + '==')
        
        # Convert to integers
        n_int = int.from_bytes(n, 'big')
        e_int = int.from_bytes(e, 'big')
        
        # Create RSA public key
        public_key = rsa.RSAPublicNumbers(e_int, n_int).public_key(default_backend())
        
        return public_key
    
    def get_public_key(self, kid: str) -> str:
        """Kid'e göre public key al"""
        jwks = self.get_jwks()
        
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                rsa_key = self.jwk_to_rsa_key(key)
                pem = rsa_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                return pem.decode('utf-8')
        
        raise Exception(f"Public key not found for kid: {kid}")
    
    def validate_token(self, token: str) -> Dict:
        try:
            # Token header'ından kid al
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get('kid')
            
            if not kid:
                raise Exception("Token does not contain kid")
            
            # Public key al
            public_key = self.get_public_key(kid)
            
            # Token doğrula (PyJWT ile proper signature verification)
            payload = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                options={
                    "verify_aud": False,        # Audience doğrulamasını kapat (Keycloak farklı kullanıyor)
                    "verify_iss": False,        # Issuer doğrulamasını kapat
                    "verify_exp": True,         # Expiry kontrolü yap
                    "verify_signature": True    # Signature kontrolü yap
                }
            )
            
            # Audit log
            self.log_auth_event("TOKEN_VALIDATED", payload.get('sub'), payload.get('preferred_username'))
            
            return payload
            
        except InvalidTokenError as e:
            self.log_auth_event("TOKEN_VALIDATION_FAILED", None, None, str(e))
            raise Exception(f"Token validation failed: {str(e)}")
        except Exception as e:
            self.log_auth_event("TOKEN_VALIDATION_FAILED", None, None, str(e))
            raise Exception(f"Token validation failed: {str(e)}")
    
    def log_auth_event(self, event_type: str, user_id: Optional[str], username: Optional[str], error: Optional[str] = None):
        """Kimlik doğrulama olaylarını logla"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'username': username,
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
            'error': error
        }
        
        logger.info(f"AUTH_EVENT: {json.dumps(log_entry)}")

class RateLimiter:
    def __init__(self, max_requests: int = 100, window_minutes: int = 15):
        self.max_requests = max_requests
        self.window_minutes = window_minutes
        self.requests = {}
        
    def is_allowed(self, identifier: str) -> bool:
        """Rate limiting kontrolü"""
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=self.window_minutes)
        
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        # Eski istekleri temizle
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if req_time > window_start
        ]
        
        # Limit kontrolü
        if len(self.requests[identifier]) >= self.max_requests:
            return False
        
        # Yeni isteği ekle
        self.requests[identifier].append(now)
        return True

# Global instances
keycloak_auth = KeycloakAuth(
    keycloak_url=os.getenv('KEYCLOAK_URL', 'http://keycloak:8080'),
    realm=os.getenv('KEYCLOAK_REALM', 'zero-trust'),
    client_id=os.getenv('KEYCLOAK_CLIENT_ID', 'zero-trust-client')
)

rate_limiter = RateLimiter(max_requests=100, window_minutes=15)

def require_auth(required_roles: List[str] = None):
    """
    Zero Trust kimlik doğrulama decorator
    Her istekte token doğrulaması yapar
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Rate limiting
            client_ip = request.remote_addr
            if not rate_limiter.is_allowed(client_ip):
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return jsonify({"error": "Rate limit exceeded"}), 429
            
            # Authorization header kontrolü
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Unauthorized - No valid token"}), 401
            
            token = auth_header.split()[1]
            
            try:
                # Token doğrula
                payload = keycloak_auth.validate_token(token)
                
                # Rol kontrolü
                if required_roles:
                    user_roles = payload.get("realm_access", {}).get("roles", [])
                    if not any(role in user_roles for role in required_roles):
                        keycloak_auth.log_auth_event(
                            "ACCESS_DENIED", 
                            payload.get('sub'), 
                            payload.get('preferred_username'),
                            f"Required roles: {required_roles}, User roles: {user_roles}"
                        )
                        return jsonify({"error": "Forbidden - Insufficient permissions"}), 403
                
                # Token payload'ını request context'e ekle
                request.user = payload
                
                return f(*args, **kwargs)
                
            except Exception as e:
                return jsonify({"error": "Unauthorized - Invalid token"}), 401
        
        return decorated_function
    return decorator

def get_user_info() -> Dict:
    """Mevcut kullanıcı bilgilerini al"""
    if hasattr(request, 'user'):
        return request.user
    return {}

def audit_log(action: str, resource: str, details: Dict = None):
    """Audit log decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_info = get_user_info()
            
            audit_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'action': action,
                'resource': resource,
                'user_id': user_info.get('sub'),
                'username': user_info.get('preferred_username'),
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent'),
                'details': details or {}
            }
            
            logger.info(f"AUDIT: {json.dumps(audit_entry)}")
            
            result = f(*args, **kwargs)
            
            # Başarılı işlem logla
            audit_entry['status'] = 'SUCCESS'
            logger.info(f"AUDIT_SUCCESS: {json.dumps(audit_entry)}")
            
            return result
        
        return decorated_function
    return decorator
