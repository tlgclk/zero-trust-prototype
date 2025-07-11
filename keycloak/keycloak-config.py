#!/usr/bin/env python3
"""
Keycloak Zero Trust Realm ve Client Konfigürasyon Scripti
"""

import requests
import json
import time
import sys

class KeycloakConfig:
    def __init__(self, base_url="http://localhost:8080", admin_user="admin", admin_password="admin"):
        self.base_url = base_url
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.access_token = None
        
    def get_admin_token(self):
        """Admin access token al"""
        token_url = f"{self.base_url}/realms/master/protocol/openid-connect/token"
        
        data = {
            'username': self.admin_user,
            'password': self.admin_password,
            'grant_type': 'password',
            'client_id': 'admin-cli'
        }
        
        try:
            response = requests.post(token_url, data=data)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data['access_token']
            print("✅ Admin token başarıyla alındı")
            return True
        except Exception as e:
            print(f"❌ Token alma hatası: {e}")
            return False
    
    def create_realm(self, realm_name="zero-trust"):
        """Zero Trust realm oluştur"""
        if not self.access_token:
            return False
            
        url = f"{self.base_url}/admin/realms"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        realm_config = {
            "realm": realm_name,
            "displayName": "Zero Trust Security Realm",
            "enabled": True,
            "sslRequired": "external",
            "registrationAllowed": False,
            "loginWithEmailAllowed": True,
            "duplicateEmailsAllowed": False,
            "resetPasswordAllowed": True,
            "editUsernameAllowed": False,
            "bruteForceProtected": True,
            "permanentLockout": False,
            "maxFailureWaitSeconds": 900,
            "minimumQuickLoginWaitSeconds": 60,
            "waitIncrementSeconds": 60,
            "quickLoginCheckMilliSeconds": 1000,
            "maxDeltaTimeSeconds": 43200,
            "failureFactor": 30,
            "accessTokenLifespan": 300,  # 5 dakika
            "accessTokenLifespanForImplicitFlow": 900,
            "ssoSessionIdleTimeout": 1800,  # 30 dakika
            "ssoSessionMaxLifespan": 36000,  # 10 saat
        }
        
        try:
            # Önce realm var mı kontrol et
            check_response = requests.get(f"{url}/{realm_name}", headers=headers)
            if check_response.status_code == 200:
                print(f"✅ Realm '{realm_name}' zaten mevcut")
                return True
                
            # Realm oluştur
            response = requests.post(url, headers=headers, json=realm_config)
            if response.status_code == 201:
                print(f"✅ Realm '{realm_name}' başarıyla oluşturuldu")
                return True
            else:
                print(f"❌ Realm oluşturma hatası: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Realm oluşturma hatası: {e}")
            return False
    
    def create_client(self, realm_name="zero-trust", client_id="zero-trust-client"):
        """Zero Trust client oluştur"""
        if not self.access_token:
            return False
            
        url = f"{self.base_url}/admin/realms/{realm_name}/clients"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        client_config = {
            "clientId": client_id,
            "name": "Zero Trust Security Client",
            "description": "Client for Zero Trust microservices authentication",
            "enabled": True,
            "clientAuthenticatorType": "client-secret",
            "secret": "zero-trust-secret-2024",
            "redirectUris": [
                "http://localhost:5001/*",
                "http://localhost:5002/*", 
                "http://localhost:5003/*",
                "https://localhost:443/*",
                "http://localhost:8080/*"
            ],
            "webOrigins": [
                "http://localhost:5001",
                "http://localhost:5002",
                "http://localhost:5003", 
                "https://localhost",
                "http://localhost:8080"
            ],
            "protocol": "openid-connect",
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "authorizationServicesEnabled": True,
            "directAccessGrantsEnabled": True,
            "implicitFlowEnabled": False,
            "standardFlowEnabled": True,
            "fullScopeAllowed": True,
            "attributes": {
                "access.token.lifespan": "300",
                "client.secret.creation.time": str(int(time.time())),
                "post.logout.redirect.uris": "+"
            }
        }
        
        try:
            # Client oluştur
            response = requests.post(url, headers=headers, json=client_config)
            if response.status_code == 201:
                print(f"✅ Client '{client_id}' başarıyla oluşturuldu")
                # Client ID'yi al
                location = response.headers.get('Location')
                if location:
                    client_uuid = location.split('/')[-1]
                    print(f"✅ Client UUID: {client_uuid}")
                return True
            else:
                print(f"❌ Client oluşturma hatası: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Client oluşturma hatası: {e}")
            return False
    
    def create_roles(self, realm_name="zero-trust"):
        """Realm rolleri oluştur"""
        if not self.access_token:
            return False
            
        url = f"{self.base_url}/admin/realms/{realm_name}/roles"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        roles = [
            {
                "name": "zero-trust-admin",
                "description": "Zero Trust Administrator with full access",
                "composite": False
            },
            {
                "name": "zero-trust-user", 
                "description": "Zero Trust User with limited access",
                "composite": False
            },
            {
                "name": "zero-trust-service",
                "description": "Zero Trust Service Account for microservices",
                "composite": False
            }
        ]
        
        for role in roles:
            try:
                response = requests.post(url, headers=headers, json=role)
                if response.status_code == 201:
                    print(f"✅ Role '{role['name']}' oluşturuldu")
                elif response.status_code == 409:
                    print(f"✅ Role '{role['name']}' zaten mevcut")
                else:
                    print(f"❌ Role '{role['name']}' oluşturma hatası: {response.status_code}")
            except Exception as e:
                print(f"❌ Role oluşturma hatası: {e}")
        
        return True
    
    def create_test_user(self, realm_name="zero-trust", username="testuser", password="testpass123"):
        """Test kullanıcısı oluştur"""
        if not self.access_token:
            return False
            
        url = f"{self.base_url}/admin/realms/{realm_name}/users"
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        user_config = {
            "username": username,
            "email": f"{username}@zerotrust.local",
            "firstName": "Test",
            "lastName": "User",
            "enabled": True,
            "emailVerified": True,
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": False
                }
            ]
        }
        
        try:
            response = requests.post(url, headers=headers, json=user_config)
            if response.status_code == 201:
                print(f"✅ Test kullanıcısı '{username}' oluşturuldu")
                return True
            elif response.status_code == 409:
                print(f"✅ Test kullanıcısı '{username}' zaten mevcut")
                return True
            else:
                print(f"❌ Kullanıcı oluşturma hatası: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            print(f"❌ Kullanıcı oluşturma hatası: {e}")
            return False
    
    def configure_zero_trust(self):
        """Tam Zero Trust konfigürasyonu"""
        print("🚀 Keycloak Zero Trust konfigürasyonu başlatılıyor...\n")
        
        # 1. Admin token al
        if not self.get_admin_token():
            return False
        
        # 2. Zero Trust realm oluştur
        if not self.create_realm():
            return False
        
        # 3. Client oluştur  
        if not self.create_client():
            return False
        
        # 4. Rolleri oluştur
        if not self.create_roles():
            return False
        
        # 5. Test kullanıcısı oluştur
        if not self.create_test_user():
            return False
        
        print("\n✅ Keycloak Zero Trust konfigürasyonu tamamlandı!")
        print(f"🌐 Admin konsol: {self.base_url}/admin")
        print(f"🔐 Zero Trust realm: {self.base_url}/realms/zero-trust")
        print(f"👤 Test kullanıcısı: testuser / testpass123")
        
        return True

def main():
    """Ana fonksiyon"""
    config = KeycloakConfig()
    
    # Keycloak hazır mı kontrol et
    try:
        health_response = requests.get("http://localhost:8080/health", timeout=5)
        if health_response.status_code != 200:
            print("❌ Keycloak sağlıklı değil, lütfen önce başlatın")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Keycloak bağlantı hatası: {e}")
        sys.exit(1)
    
    # Konfigürasyonu çalıştır
    if config.configure_zero_trust():
        print("\n🎉 Konfigürasyon başarıyla tamamlandı!")
    else:
        print("\n❌ Konfigürasyon hatası!")
        sys.exit(1)

if __name__ == "__main__":
    main()
