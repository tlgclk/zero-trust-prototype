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
RUN mkdir -p /app/shared

# Requirements kopyala ve yükle
COPY admin-service/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Shared auth utils kopyala
COPY shared/auth_utils.py /app/shared/
COPY shared/security_headers.py /app/shared/

# Uygulama dosyalarını kopyala
COPY admin-service/app.py .

# Log dizini oluştur
RUN mkdir -p /app/logs && chown -R appuser:appuser /app

# Non-root user'a geç
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

EXPOSE 5000

CMD ["python", "app.py"]
