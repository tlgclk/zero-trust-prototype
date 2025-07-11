#!/usr/bin/env python3
"""
Zero Trust Test Results Collection Wrapper
Ana dizinden reports araçlarını çalıştırmak için wrapper script
"""

import os
import sys
import subprocess
from datetime import datetime

def main():
    """Ana test ve rapor oluşturma döngüsü"""
    print("🔒 Zero Trust Security Assessment - Test & Report Generator")
    print("=" * 60)
    
    # Ana dizine git
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = script_dir
    os.chdir(project_root)
    
    # Timestamp oluştur
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print(f"📅 Timestamp: {timestamp}")
    print(f"📁 Working Directory: {project_root}")
    print()
    
    try:
        # 1. Test sonuçlarını topla
        print("🔍 1. Test sonuçları toplanıyor...")
        result = subprocess.run([
            sys.executable, 
            "reports/tools/collect_test_results.py"
        ], capture_output=True, text=True, cwd=project_root)
        
        if result.returncode == 0:
            print("✅ Test sonuçları başarıyla toplandı")
            print(result.stdout)
        else:
            print("❌ Test sonuçları toplanırken hata oluştu:")
            print(result.stderr)
            return
        
        # En son oluşturulan JSON dosyasını bul
        results_dir = os.path.join(project_root, "reports", "results")
        json_files = [f for f in os.listdir(results_dir) if f.endswith('.json') and 'security_test_results' in f]
        
        if not json_files:
            print("❌ Test sonuçları dosyası bulunamadı")
            return
            
        # En son dosyayı seç
        latest_json = sorted(json_files)[-1]
        json_path = os.path.join(results_dir, latest_json)
        
        print(f"📄 Son test dosyası: {latest_json}")
        print()
        
        # 2. HTML raporu oluştur
        print("🌐 2. HTML raporu oluşturuluyor...")
        result = subprocess.run([
            sys.executable, 
            "reports/tools/generate_html_report.py",
            json_path
        ], capture_output=True, text=True, cwd=project_root)
        
        if result.returncode == 0:
            print("✅ HTML raporu başarıyla oluşturuldu")
            print(result.stdout)
        else:
            print("❌ HTML raporu oluşturulurken hata oluştu:")
            print(result.stderr)
        
        print()
        
        # 3. Test özetini göster
        print("📊 3. Test özeti:")
        result = subprocess.run([
            sys.executable, 
            "reports/tools/show_test_summary.py",
            json_path
        ], capture_output=True, text=True, cwd=project_root)
        
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("❌ Test özeti gösterilirken hata oluştu:")
            print(result.stderr)
        
        print()
        print("🎯 Rapor Dosyaları:")
        print(f"   📄 JSON: reports/results/{latest_json}")
        html_file = latest_json.replace('.json', '_report.html')
        print(f"   🌐 HTML: reports/results/{html_file}")
        print()
        print("✨ Test ve rapor oluşturma tamamlandı!")
        
    except Exception as e:
        print(f"❌ Beklenmeyen hata: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
