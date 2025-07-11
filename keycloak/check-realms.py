import requests

# Admin token al
token_data = requests.post('http://localhost:8080/realms/master/protocol/openid-connect/token', 
                          data={'username': 'admin', 'password': 'admin', 'grant_type': 'password', 'client_id': 'admin-cli'}).json()
token = token_data['access_token']

# Realm'leri listele
realms = requests.get('http://localhost:8080/admin/realms', headers={'Authorization': f'Bearer {token}'}).json()
print('Mevcut realms:')
for realm in realms:
    print(f"  - {realm['realm']} ({realm.get('displayName', 'No display name')})")

# Zero-trust realm var mı kontrol et
zero_trust_exists = any(realm['realm'] == 'zero-trust' for realm in realms)
if zero_trust_exists:
    print("\n✅ Zero-trust realm mevcut!")
    
    # Client'leri listele
    clients = requests.get('http://localhost:8080/admin/realms/zero-trust/clients', 
                          headers={'Authorization': f'Bearer {token}'}).json()
    print("Zero-trust realm clients:")
    for client in clients:
        print(f"  - {client['clientId']}")
else:
    print("\n❌ Zero-trust realm bulunamadı")
