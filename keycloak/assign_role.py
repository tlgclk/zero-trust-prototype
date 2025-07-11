import requests

# Admin token al
print("🔧 Test kullanıcısına role atama...")
admin_token = requests.post(
    'http://localhost:8080/realms/master/protocol/openid-connect/token',
    data={
        'username': 'admin',
        'password': 'admin',
        'grant_type': 'password',
        'client_id': 'admin-cli'
    }
).json()['access_token']

print("✅ Admin token alındı")

# Test kullanıcısının ID'sini al
users = requests.get(
    'http://localhost:8080/admin/realms/zero-trust/users?username=testuser',
    headers={'Authorization': f'Bearer {admin_token}'}
).json()

if not users:
    print("❌ Test kullanıcısı bulunamadı")
    exit()

user_id = users[0]['id']
print(f"✅ Test kullanıcısı ID: {user_id}")

# Rolleri al
roles = requests.get(
    'http://localhost:8080/admin/realms/zero-trust/roles',
    headers={'Authorization': f'Bearer {admin_token}'}
).json()

# zero-trust-user rolünü bul
zero_trust_user_role = None
for role in roles:
    if role['name'] == 'zero-trust-user':
        zero_trust_user_role = role
        break

if not zero_trust_user_role:
    print("❌ zero-trust-user rolü bulunamadı")
    exit()

print(f"✅ zero-trust-user role bulundu: {zero_trust_user_role['id']}")

# Kullanıcıya rol ata
response = requests.post(
    f'http://localhost:8080/admin/realms/zero-trust/users/{user_id}/role-mappings/realm',
    headers={
        'Authorization': f'Bearer {admin_token}',
        'Content-Type': 'application/json'
    },
    json=[zero_trust_user_role]
)

if response.status_code in [201, 204]:
    print("✅ Role başarıyla atandı!")
else:
    print(f"❌ Role atama hatası: {response.status_code} - {response.text}")

print("🎯 Role atama tamamlandı")
