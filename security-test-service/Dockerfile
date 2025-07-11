FROM python:3.11-slim

# Güvenlik güncellemeleri
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user oluştur
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Shared modules için dizin oluştur
RUN mkdir -p /app/shared /app/zap

# Requirements kopyala ve yükle
COPY security-test-service/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Shared auth utils kopyala (opsiyonel)
# COPY shared/auth_utils.py /app/shared/

# ZAP scanner kopyala (opsiyonel)
# COPY security-test-service/zap/zap_scanner.py /app/zap/

# Enhanced security tests kopyala (opsiyonel)
# COPY security-test-service/enhanced_security_tests.py /app/

# Uygulama dosyalarını kopyala - enhanced versiyon
COPY security-test-service/app_simple.py app.py
COPY security-test-service/zero_trust_security_tests.py zero_trust_security_tests.py
COPY security-test-service/enhanced_security_tests.py enhanced_security_tests.py

# Log dizini oluştur
RUN mkdir -p /app/logs && chown -R appuser:appuser /app

# Non-root user'a geç
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

EXPOSE 5000

CMD ["python", "app.py"]
