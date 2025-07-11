#!/usr/bin/env python3
"""
Zero Trust Network Penetration Testing Script
Nmap tabanlı ağ tarama ve güvenlik testi
"""

import subprocess
import json
from datetime import datetime
import sys

class ZeroTrustPenTest:
    def __init__(self):
        self.target_network = "172.20.0.0/16"
        self.target_services = [
            {"name": "keycloak", "host": "localhost", "port": 8080},
            {"name": "user-service", "host": "localhost", "port": 5001},
            {"name": "admin-service", "host": "localhost", "port": 5002},
            {"name": "security-service", "host": "localhost", "port": 5003},
            {"name": "nginx-https", "host": "localhost", "port": 443},
            {"name": "nginx-http", "host": "localhost", "port": 80},
            {"name": "prometheus", "host": "localhost", "port": 9090},
            {"name": "grafana", "host": "localhost", "port": 3000}
        ]
        self.results = {}

    def network_discovery(self):
        """Ağ keşfi - hangi hostlar aktif"""
        print("🔍 Zero Trust Network Discovery...")
        
        try:
            # Daha hızlı ve hedefli network discovery
            cmd = ["nmap", "-sn", "-T4", "localhost"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            self.results["network_discovery"] = {
                "status": "success" if result.returncode == 0 else "failed",
                "output": result.stdout,
                "errors": result.stderr,
                "timestamp": datetime.now().isoformat()
            }
            
            print(f"✅ Network discovery completed")
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            print("❌ Network discovery timeout")
            self.results["network_discovery"] = {
                "status": "timeout",
                "output": "",
                "errors": "Network discovery timeout",
                "timestamp": datetime.now().isoformat()
            }
            return False
        except Exception as e:
            print(f"❌ Network discovery error: {e}")
            return False

    def port_scan(self):
        """Port tarama - açık portları tespit et"""
        print("🔍 Zero Trust Port Scanning...")
        
        self.results["port_scans"] = {}
        
        for service in self.target_services:
            print(f"  📡 Scanning {service['name']} ({service['host']}:{service['port']})...")
            
            try:
                # Daha hızlı ve basit port scan
                cmd = [
                    "nmap", "-sS", "-T4", "--max-retries=1",
                    f"{service['host']}", "-p", str(service['port'])
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                self.results["port_scans"][service['name']] = {
                    "status": "success" if result.returncode == 0 else "failed",
                    "output": result.stdout,
                    "errors": result.stderr,
                    "timestamp": datetime.now().isoformat(),
                    "port": service['port']
                }
                
                if "open" in result.stdout.lower():
                    print(f"    ✅ {service['name']} - Port {service['port']} is open")
                else:
                    print(f"    ❌ {service['name']} - Port {service['port']} appears closed/filtered")
                    
            except subprocess.TimeoutExpired:
                print(f"    ⏰ {service['name']} scan timeout")
                self.results["port_scans"][service['name']] = {
                    "status": "timeout",
                    "output": "",
                    "errors": "Port scan timeout",
                    "timestamp": datetime.now().isoformat(),
                    "port": service['port']
                }
            except Exception as e:
                print(f"    ❌ {service['name']} scan error: {e}")
                self.results["port_scans"][service['name']] = {
                    "status": "error",
                    "output": "",
                    "errors": str(e),
                    "timestamp": datetime.now().isoformat(),
                    "port": service['port']
                }

    def vulnerability_scan(self):
        """Güvenlik açığı tarama"""
        print("🔍 Zero Trust Vulnerability Scanning...")
        
        self.results["vulnerability_scans"] = {}
        
        # Web servisleri için özel tarama
        web_services = ["keycloak", "user-service", "admin-service", "security-service", "nginx-https"]
        
        for service_name in web_services:
            service = next((s for s in self.target_services if s['name'] == service_name), None)
            if not service:
                continue
                
            print(f"  🔍 Vulnerability scan for {service['name']}...")
            
            try:
                # HTTP service scan
                cmd = [
                    "nmap", "-sS", "--script=http-vuln*,ssl-*",
                    f"{service['host']}", "-p", str(service['port'])
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                self.results["vulnerability_scans"][service['name']] = {
                    "status": "success" if result.returncode == 0 else "failed",
                    "output": result.stdout,
                    "errors": result.stderr,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Güvenlik açığı analizi
                if "VULNERABLE" in result.stdout.upper():
                    print(f"    ⚠️  {service['name']} - Potential vulnerabilities detected!")
                else:
                    print(f"    ✅ {service['name']} - No obvious vulnerabilities")
                    
            except subprocess.TimeoutExpired:
                print(f"    ⏰ {service['name']} vulnerability scan timeout")
                self.results["vulnerability_scans"][service['name']] = {
                    "status": "timeout",
                    "output": "",
                    "errors": "Vulnerability scan timeout",
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                print(f"    ❌ {service['name']} vulnerability scan error: {e}")
                self.results["vulnerability_scans"][service['name']] = {
                    "status": "error",
                    "output": "",
                    "errors": str(e),
                    "timestamp": datetime.now().isoformat()
                }

    def brute_force_test(self):
        """Brute force saldırı simülasyonu"""
        print("🔍 Zero Trust Brute Force Testing...")
        
        self.results["brute_force_tests"] = {}
        
        # Keycloak admin panel brute force test
        print("  🔨 Testing Keycloak admin authentication...")
        
        try:
            # Basit HTTP auth test
            cmd = [
                "nmap", "--script=http-brute",
                "--script-args=http-brute.path=/auth/admin",
                "localhost", "-p", "8080"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            self.results["brute_force_tests"]["keycloak_admin"] = {
                "status": "success" if result.returncode == 0 else "failed",
                "output": result.stdout,
                "errors": result.stderr,
                "timestamp": datetime.now().isoformat()
            }
            
            if "Discovered credentials" in result.stdout:
                print("    ⚠️  Weak credentials detected!")
            else:
                print("    ✅ No weak credentials found")
                
        except subprocess.TimeoutExpired:
            print("    ⏰ Brute force test timeout")
            self.results["brute_force_tests"]["keycloak_admin"] = {
                "status": "timeout",
                "output": "",
                "errors": "Brute force test timeout",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            print(f"    ❌ Brute force test error: {e}")
            self.results["brute_force_tests"]["keycloak_admin"] = {
                "status": "error",
                "output": "",
                "errors": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def ssl_tls_test(self):
        """SSL/TLS güvenlik testi"""
        print("🔍 Zero Trust SSL/TLS Security Testing...")
        
        self.results["ssl_tests"] = {}
        
        # HTTPS servisleri test et
        https_services = [
            {"name": "nginx-https", "host": "localhost", "port": 443}
        ]
        
        for service in https_services:
            print(f"  🔒 Testing SSL/TLS for {service['name']}...")
            
            try:
                cmd = [
                    "nmap", "--script=ssl-*,tls-*",
                    f"{service['host']}", "-p", str(service['port'])
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                self.results["ssl_tests"][service['name']] = {
                    "status": "success" if result.returncode == 0 else "failed",
                    "output": result.stdout,
                    "errors": result.stderr,
                    "timestamp": datetime.now().isoformat()
                }
                
                # SSL/TLS analizi
                if "SSLv" in result.stdout or "TLSv1.0" in result.stdout or "TLSv1.1" in result.stdout:
                    print(f"    ⚠️  {service['name']} - Weak SSL/TLS protocols detected!")
                else:
                    print(f"    ✅ {service['name']} - SSL/TLS configuration appears secure")
                    
            except subprocess.TimeoutExpired:
                print(f"    ⏰ {service['name']} SSL test timeout")
                self.results["ssl_tests"][service['name']] = {
                    "status": "timeout",
                    "output": "",
                    "errors": "SSL test timeout",
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                print(f"    ❌ {service['name']} SSL test error: {e}")
                self.results["ssl_tests"][service['name']] = {
                    "status": "error",
                    "output": "",
                    "errors": str(e),
                    "timestamp": datetime.now().isoformat()
                }

    def generate_report(self):
        """Penetrasyon testi raporu oluştur"""
        print("📄 Generating Zero Trust Penetration Test Report...")
        
        # Test sonuçlarını detaylı hesapla
        total_tests = 0
        completed_tests = 0
        failed_tests = 0
        timeout_tests = 0
        
        # Her test kategorisini analiz et
        for category, results in self.results.items():
            if category == "network_discovery":
                # Network discovery tek bir test
                total_tests += 1
                status = results.get("status", "unknown")
                if status == "success":
                    completed_tests += 1
                elif status == "failed":
                    failed_tests += 1
                elif status == "timeout":
                    timeout_tests += 1
            else:
                # Diğer kategoriler servis bazlı
                if isinstance(results, dict):
                    for service_name, service_result in results.items():
                        total_tests += 1
                        status = service_result.get("status", "unknown")
                        if status == "success":
                            completed_tests += 1
                        elif status == "failed":
                            failed_tests += 1
                        elif status == "timeout":
                            timeout_tests += 1
        
        success_rate = (completed_tests / total_tests * 100) if total_tests > 0 else 0
        
        report = {
            "test_metadata": {
                "target_network": self.target_network,
                "test_timestamp": datetime.now().isoformat(),
                "test_type": "Zero Trust Network Penetration Test",
                "services_tested": len(self.target_services)
            },
            "results": self.results,
            "summary": {
                "total_tests": total_tests,
                "completed_tests": completed_tests,
                "failed_tests": failed_tests,
                "timeout_tests": timeout_tests,
                "success_rate": f"{success_rate:.1f}%"
            }
        }
        
        # JSON raporu kaydet
        with open("zero_trust_pentest_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Özet rapor yazdır
        print("\n" + "="*60)
        print("🎯 ZERO TRUST PENETRATION TEST SUMMARY")
        print("="*60)
        print(f"📅 Test Date: {report['test_metadata']['test_timestamp']}")
        print(f"🎯 Target Network: {report['test_metadata']['target_network']}")
        print(f"🔧 Services Tested: {report['test_metadata']['services_tested']}")
        print(f"✅ Completed Tests: {report['summary']['completed_tests']}")
        print(f"❌ Failed Tests: {report['summary']['failed_tests']}")
        print(f"⏰ Timeout Tests: {report['summary']['timeout_tests']}")
        print(f"📊 Success Rate: {report['summary']['success_rate']}")
        print("="*60)
        
        return report

    def run_full_test(self):
        """Tam penetrasyon testi süiti çalıştır"""
        print("🚀 Starting Zero Trust Penetration Testing Suite...")
        print("="*60)
        
        # Test sırası
        tests = [
            ("Network Discovery", self.network_discovery),
            ("Port Scanning", self.port_scan),
            ("Vulnerability Scanning", self.vulnerability_scan),
            ("Brute Force Testing", self.brute_force_test),
            ("SSL/TLS Testing", self.ssl_tls_test)
        ]
        
        for test_name, test_func in tests:
            print(f"\n🔄 Running {test_name}...")
            try:
                test_func()
            except Exception as e:
                print(f"❌ {test_name} failed: {e}")
        
        # Rapor oluştur
        print(f"\n📊 Generating final report...")
        report = self.generate_report()
        
        print(f"✅ Zero Trust Penetration Test completed!")
        print(f"📄 Report saved to: zero_trust_pentest_report.json")
        
        return report

def main():
    """Ana fonksiyon"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("""
Zero Trust Network Penetration Testing Tool

Usage:
    python nmap_scan.py              # Run full penetration test suite
    python nmap_scan.py --help       # Show this help message

Prerequisites:
    - nmap must be installed and in PATH
    - Zero Trust Docker environment must be running
    - Run with appropriate permissions for network scanning

Test Coverage:
    - Network Discovery
    - Port Scanning  
    - Vulnerability Assessment
    - Brute Force Testing
    - SSL/TLS Security Testing
        """)
        return
    
    # Nmap kurulu mu kontrol et
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Error: nmap is not installed or not in PATH")
        print("   Please install nmap: https://nmap.org/download.html")
        return
    
    # Penetrasyon testini başlat
    pentest = ZeroTrustPenTest()
    pentest.run_full_test()

if __name__ == "__main__":
    main()
