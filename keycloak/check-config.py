import requests

# Admin token al
token_data = requests.post('http://localhost:8080/realms/master/protocol/openid-connect/token', 
                          data={'username': 'admin', 'password': 'admin', 'grant_type': 'password', 'client_id': 'admin-cli'}).json()
token = token_data['access_token']

print("🔧 Zero Trust Realm Konfigürasyon Detayları:\n")

# OpenID Connect endpoints
print("📋 OpenID Connect Endpoints:")
try:
    oidc_config = requests.get('http://localhost:8080/realms/zero-trust/.well-known/openid_configuration').json()
    print(f"  - Issuer: {oidc_config['issuer']}")
    print(f"  - Auth Endpoint: {oidc_config['authorization_endpoint']}")
    print(f"  - Token Endpoint: {oidc_config['token_endpoint']}")
    print(f"  - UserInfo Endpoint: {oidc_config['userinfo_endpoint']}")
except Exception as e:
    print(f"  ❌ OIDC endpoints hatası: {e}")

# Client detayları
print("\n🔐 Zero Trust Client Detayları:")
try:
    clients = requests.get('http://localhost:8080/admin/realms/zero-trust/clients', 
                          headers={'Authorization': f'Bearer {token}'}).json()
    
    zero_trust_client = next((client for client in clients if client['clientId'] == 'zero-trust-client'), None)
    if zero_trust_client:
        print(f"  - Client ID: {zero_trust_client['clientId']}")
        print(f"  - Client UUID: {zero_trust_client['id']}")
        print(f"  - Enabled: {zero_trust_client['enabled']}")
        print(f"  - Protocol: {zero_trust_client['protocol']}")
        print(f"  - Public Client: {zero_trust_client['publicClient']}")
        print(f"  - Service Accounts Enabled: {zero_trust_client['serviceAccountsEnabled']}")
        print(f"  - Redirect URIs: {zero_trust_client.get('redirectUris', [])}")
except Exception as e:
    print(f"  ❌ Client detayları hatası: {e}")

# Roller
print("\n👤 Realm Rolleri:")
try:
    roles = requests.get('http://localhost:8080/admin/realms/zero-trust/roles', 
                        headers={'Authorization': f'Bearer {token}'}).json()
    for role in roles:
        print(f"  - {role['name']}: {role.get('description', 'No description')}")
except Exception as e:
    print(f"  ❌ Roller hatası: {e}")

# Kullanıcılar
print("\n👥 Kullanıcılar:")
try:
    users = requests.get('http://localhost:8080/admin/realms/zero-trust/users', 
                        headers={'Authorization': f'Bearer {token}'}).json()
    for user in users:
        print(f"  - {user['username']} ({user.get('email', 'No email')}) - Enabled: {user['enabled']}")
except Exception as e:
    print(f"  ❌ Kullanıcılar hatası: {e}")

print("\n🎯 Test Token Alma:")
try:
    # Test kullanıcısı ile token alma
    test_token = requests.post('http://localhost:8080/realms/zero-trust/protocol/openid-connect/token',
                              data={
                                  'username': 'testuser',
                                  'password': 'testpass123',
                                  'grant_type': 'password',
                                  'client_id': 'zero-trust-client',
                                  'client_secret': 'zero-trust-secret-2024'
                              })
    if test_token.status_code == 200:
        token_info = test_token.json()
        print(f"  ✅ Token başarıyla alındı! (expires_in: {token_info.get('expires_in')} saniye)")
        print(f"  🔑 Access token type: {token_info.get('token_type')}")
    else:
        print(f"  ❌ Token alma hatası: {test_token.status_code} - {test_token.text}")
except Exception as e:
    print(f"  ❌ Token test hatası: {e}")
