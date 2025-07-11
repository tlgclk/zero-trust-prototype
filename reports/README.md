# Reports Directory

Bu klasör Zero Trust prototipinin güvenlik test sonuçları ve raporlarını içerir.

## 📁 Klasör Yapısı

### `tools/` - Rapor Oluşturma Araçları
- `collect_test_results.py` - Otomatik güvenlik test sonuçlarını toplama aracı
- `generate_html_report.py` - JSON test sonuçlarını HTML formatına dönüştürme aracı
- `show_test_summary.py` - Test sonuçlarının konsol özetini gösterme aracı
- `run_security_assessment.py` - Ana wrapper script (tüm araçları çalıştırır)

### `results/` - Test Sonuçları ve Raporlar
- `security_test_results_*.json` - JSON formatında detaylı test sonuçları
- `security_test_results_*_report.html` - HTML formatında görsel test raporları
- `zero_trust_pentest_report.json` - Penetration testing sonuçları

## 🔧 Araçların Kullanımı

### Tek Komutla Tüm İşlemler (Ana Dizinden)
```bash
python security_assessment.py
```

### Manuel Araç Kullanımı

#### Test Sonuçlarını Toplama
```bash
python reports/tools/collect_test_results.py
```

#### HTML Raporu Oluşturma
```bash
python reports/tools/generate_html_report.py reports/results/security_test_results_YYYYMMDD_HHMMSS.json
```

#### Test Özeti Görüntüleme
```bash
python reports/tools/show_test_summary.py reports/results/security_test_results_YYYYMMDD_HHMMSS.json
```

#### Tüm İşlemleri Otomatik Çalıştırma
```bash
python reports/tools/run_security_assessment.py
```

## 📊 Rapor Içeriği

### JSON Test Sonuçları İçerir:
- System health status
- Security test results
- JWT authentication tests
- Input validation tests
- Compliance assessments (NIST Zero Trust, OWASP Top 10)
- Performance metrics

### HTML Raporları İçerir:
- Interactive dashboard
- Visual test result indicators
- Detailed test breakdowns
- Professional styling
- Easy sharing and presentation format

## 📅 Dosya Adlandırma

Test sonuçları dosyaları `YYYYMMDD_HHMMSS` formatında timestamp içerir:
- `security_test_results_20250711_144536.json`
- `security_test_results_20250711_144536_report.html`

Bu format ile kronolojik sıralama ve versiyonlama kolaylaşır.

## 🎯 Kullanım Notları

1. Test araçları proje ana dizininden çalıştırılmalıdır
2. HTML raporları modern web tarayıcılarında açılabilir
3. JSON dosyaları otomatik analiz ve entegrasyon için kullanılabilir
4. Tüm raporlar güvenlik assessment dökümanlarında referans olarak kullanılabilir

## 🔄 Otomatik Test Döngüsü

### Tek Komut (Önerilen)
```bash
# Ana dizinden
python security_assessment.py
```

### Manuel Adımlar
```bash
# 1. Test sonuçlarını topla
python reports/tools/collect_test_results.py

# 2. HTML raporu oluştur  
python reports/tools/generate_html_report.py reports/results/security_test_results_$(Get-Date -Format "yyyyMMdd_HHmmss").json

# 3. Özeti görüntüle
python reports/tools/show_test_summary.py reports/results/security_test_results_$(Get-Date -Format "yyyyMMdd_HHmmss").json

# 4. Veya tüm işlemleri otomatik çalıştır
python reports/tools/run_security_assessment.py
```

Bu araçlarla Zero Trust prototipinin güvenlik durumu düzenli olarak izlenebilir ve raporlanabilir.
