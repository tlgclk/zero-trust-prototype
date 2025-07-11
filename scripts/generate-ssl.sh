#!/bin/bash

# Zero Trust SSL Certificate Generation Script
# Self-signed certificate for development/testing

echo "🔐 Zero Trust SSL Certificate Generation"
echo "========================================"

# Create SSL directory
mkdir -p nginx/ssl

# Generate private key
echo "📝 Generating private key..."
openssl genrsa -out nginx/ssl/server.key 2048

# Generate certificate signing request
echo "📝 Generating certificate signing request..."
openssl req -new -key nginx/ssl/server.key -out nginx/ssl/server.csr -subj "/C=TR/ST=Istanbul/L=Istanbul/O=Zero Trust Organization/OU=IT Department/CN=localhost"

# Generate self-signed certificate
echo "📝 Generating self-signed certificate..."
openssl x509 -req -days 365 -in nginx/ssl/server.csr -signkey nginx/ssl/server.key -out nginx/ssl/server.crt

# Set proper permissions
chmod 600 nginx/ssl/server.key
chmod 644 nginx/ssl/server.crt

# Clean up
rm nginx/ssl/server.csr

echo "✅ SSL Certificate generated successfully!"
echo "📁 Certificate location: nginx/ssl/server.crt"
echo "🔑 Private key location: nginx/ssl/server.key"
echo ""
echo "⚠️  WARNING: This is a self-signed certificate for development only!"
echo "   For production, use certificates from a trusted CA."
