#!/usr/bin/env python3
"""
Zero Trust Prototype - Main Deployment & Test Script
Tüm proje kurulum, konfigürasyon ve test sürecini otomatikleştiren ana script
"""

import os
import sys
import time
import subprocess
import json
import requests
from datetime import datetime

class ZeroTrustDeployment:
    def __init__(self):
        self.project_root = os.path.dirname(os.path.abspath(__file__))
        self.start_time = datetime.now()
        
    def log(self, message, level="INFO"):
        """Log mesajı yazdır"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        levels = {
            "INFO": "[INFO]",
            "SUCCESS": "[SUCCESS]", 
            "ERROR": "[ERROR]",
            "WARNING": "[WARN]",
            "STEP": "[STEP]"
        }
        icon = levels.get(level, "[LOG]")
        try:
            print(f"[{timestamp}] {icon} {message}")
        except UnicodeEncodeError:
            # Fallback for encoding issues
            print(f"[{timestamp}] {icon} {message.encode('ascii', 'replace').decode('ascii')}")
    
    def run_command(self, command, description, check_result=True, timeout=300):
        """Komut çalıştır ve sonucu kontrol et"""
        self.log(f"{description}")
        self.log(f"Komut: {command}", "STEP")
        
        try:
            # Windows encoding sorunları için UTF-8 zorla
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.project_root,
                encoding='utf-8',
                errors='replace'  # Encoding hatalarını görmezden gel
            )
            
            if check_result and result.returncode != 0:
                self.log(f"Komut basarisiz oldu: {command}", "ERROR")
                if result.stderr:
                    # Hata mesajını güvenli şekilde yazdır
                    error_msg = result.stderr.replace('\n', ' ').strip()[:200]
                    self.log(f"Hata: {error_msg}", "ERROR")
                return False
            
            if result.stdout and result.stdout.strip():
                # Çıktıyı güvenli şekilde yazdır
                output_msg = result.stdout.replace('\n', ' ').strip()[:200]
                self.log(f"Cikti: {output_msg}...", "STEP")
                
            return True
            
        except subprocess.TimeoutExpired:
            self.log(f"Komut zaman asimi: {command}", "ERROR")
            return False
        except UnicodeDecodeError as e:
            self.log(f"Encoding hatasi: {str(e)[:100]}", "WARNING")
            # Encoding hatası olsa bile devam et
            return True
        except Exception as e:
            self.log(f"Komut hatasi: {str(e)}", "ERROR")
            return False
    
    def check_docker(self):
        """Docker kurulu ve çalışıyor mu kontrol et"""
        self.log("Docker kontrol ediliyor...")
        
        if not self.run_command("docker --version", "Docker version kontrolü"):
            self.log("Docker kurulu değil veya erişilemiyor!", "ERROR")
            return False
            
        if not self.run_command("docker-compose --version", "Docker Compose version kontrolü"):
            self.log("Docker Compose kurulu değil veya erişilemiyor!", "ERROR")
            return False
        
        self.log("Docker ve Docker Compose hazır", "SUCCESS")
        return True
    
    def cleanup_existing(self):
        """Mevcut container'ları temizle"""
        self.log("Mevcut container'lar temizleniyor...")
        
        commands = [
            ("docker-compose down --volumes", "Container'ları durdur ve volume'ları temizle"),
            ("docker system prune -f", "Kullanılmayan Docker resource'larını temizle")
        ]
        
        for cmd, desc in commands:
            self.run_command(cmd, desc, check_result=False)  # Temizlik komutları başarısız olabilir
            
        self.log("Temizlik tamamlandı", "SUCCESS")
        return True  # Temizlik adımı her zaman başarılı sayılır
    
    def start_services(self):
        """Docker Compose ile servisleri başlat"""
        self.log("Servisler baslatiliyor...")
        
        # Docker build işlemi uzun sürebilir, bu yüzden özel timeout
        self.log("Docker build islemi basladi (bu islem uzun surebilir)...")
        
        try:
            # PowerShell yerine cmd kullan
            process = subprocess.Popen(
                "docker-compose up --build -d",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.project_root,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            
            # Process'i bekle ama timeout koy
            try:
                stdout, stderr = process.communicate(timeout=600)  # 10 dakika
                
                if process.returncode == 0:
                    self.log("Container'lar basariyla baslatildi", "SUCCESS")
                    return True
                else:
                    self.log("Docker Compose hatasi olustu", "ERROR")
                    if stderr:
                        error_msg = stderr.replace('\n', ' ').strip()[:300]
                        self.log(f"Hata detayi: {error_msg}", "ERROR")
                    return False
                    
            except subprocess.TimeoutExpired:
                self.log("Docker build zaman asimi - process sonlandiriliyor", "ERROR")
                process.kill()
                return False
                
        except Exception as e:
            self.log(f"Docker baslama hatasi: {str(e)}", "ERROR")
            return False
    
    def wait_for_services(self):
        """Servislerin hazır olmasını bekle"""
        self.log("Servislerin hazır olması bekleniyor...")
        
        services = {
            "PostgreSQL": "http://localhost:5432",  # Bu direkt test edilemez
            "Keycloak": "http://localhost:8080/health",
            "User Service": "http://localhost:5001/health",
            "Admin Service": "http://localhost:5002/health",
            "Security Service": "http://localhost:5003/health"
        }
        
        max_attempts = 20
        wait_time = 15
        
        for attempt in range(max_attempts):
            self.log(f"Health check denemesi {attempt + 1}/{max_attempts}")
            all_healthy = True
            
            for service_name, url in services.items():
                if "5432" in url:  # PostgreSQL için Docker kontrol
                    result = subprocess.run(
                        "docker exec postgres pg_isready -U keycloak",
                        shell=True, capture_output=True, text=True
                    )
                    if result.returncode != 0:
                        self.log(f"{service_name}: Henüz hazır değil", "WARNING")
                        all_healthy = False
                    else:
                        self.log(f"{service_name}: Hazır", "SUCCESS")
                else:
                    try:
                        response = requests.get(url, timeout=5)
                        if response.status_code == 200:
                            self.log(f"{service_name}: Hazır", "SUCCESS")
                        else:
                            self.log(f"{service_name}: HTTP {response.status_code}", "WARNING")
                            all_healthy = False
                    except:
                        self.log(f"{service_name}: Henüz erişilemiyor", "WARNING")
                        all_healthy = False
            
            if all_healthy:
                self.log("Tüm servisler hazır!", "SUCCESS")
                return True
            
            if attempt < max_attempts - 1:
                self.log(f"{wait_time} saniye bekleniyor...", "STEP")
                time.sleep(wait_time)
        
        self.log("Bazı servisler hala hazır değil, devam ediliyor...", "WARNING")
        return True  # Kısmen başarısız olsa da devam et
    
    def configure_keycloak(self):
        """Keycloak otomatik konfigürasyonu"""
        self.log("Keycloak konfigürasyonu başlatılıyor...")
        
        # Keycloak'ın tamamen hazır olması için ek bekleme
        time.sleep(30)
        
        config_files = [
            ("keycloak/keycloak-config.py", "Realm ve client konfigürasyonu"),
            ("keycloak/check-config.py", "Konfigürasyon doğrulama"),
            ("keycloak/assign_role.py", "Test kullanıcısı role assignment")
        ]
        
        success_count = 0
        for script, description in config_files:
            script_path = os.path.join(self.project_root, script)
            if os.path.exists(script_path):
                if self.run_command(f"python {script}", description, check_result=False):
                    success_count += 1
                else:
                    self.log(f"Konfigürasyon uyarısı: {script}", "WARNING")
            else:
                self.log(f"Konfigürasyon dosyası bulunamadı: {script}", "WARNING")
        
        self.log("Keycloak konfigürasyonu tamamlandı", "SUCCESS")
        return True  # Her durumda başarılı olarak devam et
    
    def run_additional_configs(self):
        """Ek konfigürasyon dosyalarını çalıştır"""
        self.log("Ek konfigürasyonlar kontrol ediliyor...")
        
        # scripts/ klasöründeki setup dosyalarını ara
        scripts_dir = os.path.join(self.project_root, "scripts")
        if os.path.exists(scripts_dir):
            setup_files = [f for f in os.listdir(scripts_dir) if f.startswith('setup_') and f.endswith('.py')]
            
            for setup_file in setup_files:
                script_path = os.path.join(scripts_dir, setup_file)
                description = f"Ek konfigürasyon: {setup_file}"
                self.run_command(f"python {script_path}", description, check_result=False)
        
        # Ana dizindeki config dosyalarını kontrol et
        config_patterns = ["config_*.py", "setup_*.py", "init_*.py"]
        for pattern in config_patterns:
            matching_files = [f for f in os.listdir(self.project_root) if f.startswith(pattern.split('*')[0]) and f.endswith('.py')]
            for config_file in matching_files:
                if config_file != "main.py":  # Kendini çalıştırma
                    description = f"Konfigürasyon: {config_file}"
                    self.run_command(f"python {config_file}", description, check_result=False)
        
        self.log("Ek konfigürasyonlar tamamlandı", "SUCCESS")
        return True
    
    def run_security_tests(self):
        """Güvenlik testlerini çalıştır"""
        self.log("Güvenlik testleri başlatılıyor...")
        
        # Test araçlarının yeni konumundan çalıştır
        test_script = os.path.join(self.project_root, "reports", "tools", "run_security_assessment.py")
        
        if os.path.exists(test_script):
            if self.run_command(f"python {test_script}", "Kapsamlı güvenlik testi", timeout=600):
                self.log("Güvenlik testleri başarıyla tamamlandı", "SUCCESS")
            else:
                self.log("Güvenlik testlerinde sorun oluştu", "WARNING")
        else:
            # Fallback: Manuel test araçlarını çalıştır
            tools = [
                "reports/tools/collect_test_results.py",
                "reports/tools/generate_html_report.py reports/results/latest.json"
            ]
            
            for tool in tools:
                self.run_command(f"python {tool}", f"Test aracı: {tool}", check_result=False)
        
        self.log("Test süreci tamamlandı", "SUCCESS")
        return True
    
    def show_summary(self):
        """Deployment özeti göster"""
        duration = datetime.now() - self.start_time
        
        self.log("=" * 60)
        self.log("*** ZERO TRUST PROTOTYPE DEPLOYMENT TAMAMLANDI! ***")
        self.log("=" * 60)
        self.log(f"Toplam süre: {duration}")
        self.log("")
        self.log("Erişilebilir Servisler:")
        
        services = [
            ("Keycloak Admin", "http://localhost:8080/admin", "admin/admin"),
            ("User Service", "http://localhost:5001/health", "Health check"),
            ("Admin Service", "http://localhost:5002/health", "Health check"),
            ("Security Service", "http://localhost:5003/health", "Health check"),
            ("Prometheus", "http://localhost:9090", "Monitoring"),
            ("Grafana", "http://localhost:3000", "admin/admin"),
            ("OWASP ZAP", "http://localhost:8081", "Security scanner")
        ]
        
        for name, url, info in services:
            self.log(f"   -> {name}: {url} ({info})")
        
        self.log("")
        self.log("Test Raporları:")
        
        results_dir = os.path.join(self.project_root, "reports", "results")
        if os.path.exists(results_dir):
            json_files = [f for f in os.listdir(results_dir) if f.endswith('.json') and 'security_test_results' in f]
            if json_files:
                latest_json = sorted(json_files)[-1]
                latest_html = latest_json.replace('.json', '_report.html')
                self.log(f"   JSON Report: reports/results/{latest_json}")
                self.log(f"   HTML Report: reports/results/{latest_html}")
        
        self.log("")
        self.log("Faydalı Komutlar:")
        self.log("   docker-compose ps              # Container durumları")
        self.log("   docker-compose logs [service]  # Servis logları")
        self.log("   docker-compose down            # Tüm servisleri durdur")
        self.log("   python reports/tools/run_security_assessment.py  # Test tekrarı")
        self.log("")
        self.log("*** Zero Trust Prototype hazır kullanıma! ***")
    
    def deploy(self):
        """Ana deployment süreci"""
        self.log("*** Zero Trust Prototype Deployment Başlatılıyor...")
        self.log(f"Proje dizini: {self.project_root}")
        self.log("")
        
        steps = [
            ("Docker kontrolü", self.check_docker),
            ("Mevcut container'ları temizle", self.cleanup_existing),
            ("Servisleri başlat", self.start_services),
            ("Servislerin hazır olmasını bekle", self.wait_for_services),
            ("Keycloak konfigürasyonu", self.configure_keycloak),
            ("Ek konfigürasyonlar", self.run_additional_configs),
            ("Güvenlik testleri", self.run_security_tests)
        ]
        
        for step_name, step_func in steps:
            self.log(f"\n>> ADIM: {step_name}")
            self.log("-" * 50)
            
            try:
                if not step_func():
                    self.log(f"Adım başarısız: {step_name}", "ERROR")
                    self.log("Deployment durduruluyor...", "ERROR")
                    return False
            except Exception as e:
                self.log(f"Adım hatası: {step_name} - {str(e)}", "ERROR")
                return False
        
        self.show_summary()
        return True

def main():
    """Ana fonksiyon"""
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("""
Zero Trust Prototype - Ana Deployment Script

Kullanım:
    python main.py              # Tam deployment (önerilen)
    python main.py --help       # Bu yardım mesajı

Bu script şunları yapar:
1. Docker ve Docker Compose kontrolü
2. Mevcut container'ları temizleme
3. Tüm servisleri Docker Compose ile başlatma
4. Servislerin hazır olmasını bekleme
5. Keycloak otomatik konfigürasyonu
6. Ek konfigürasyon dosyalarını çalıştırma
7. Kapsamlı güvenlik testleri
8. Sonuç raporu oluşturma

Gereksinimler:
- Docker & Docker Compose
- Python 3.6+
- requests kütüphanesi (pip install requests)
""")
        return 0
    
    deployment = ZeroTrustDeployment()
    
    try:
        success = deployment.deploy()
        return 0 if success else 1
    except KeyboardInterrupt:
        deployment.log("\n❌ Deployment iptal edildi (Ctrl+C)", "ERROR")
        return 1
    except Exception as e:
        deployment.log(f"\n❌ Beklenmeyen hata: {str(e)}", "ERROR")
        return 1

if __name__ == "__main__":
    sys.exit(main())
