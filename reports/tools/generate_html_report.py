#!/usr/bin/env python3
"""
Zero Trust Security Test Results HTML Report Generator
JSON test sonuçlarından HTML raporu oluşturur
"""

import json
import sys
import datetime
from pathlib import Path

class HTMLReportGenerator:
    def __init__(self, json_file):
        self.json_file = json_file
        self.data = None
        self.load_data()
    
    def load_data(self):
        """JSON dosyasını yükle"""
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
        except Exception as e:
            print(f"JSON dosyası yüklenemedi: {e}")
            sys.exit(1)
    
    def generate_html(self):
        """HTML raporu oluştur"""
        html = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero Trust Security Test Results</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007acc;
            margin: 0;
            font-size: 2.5em;
        }}
        .header .subtitle {{
            color: #666;
            margin-top: 10px;
            font-size: 1.1em;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .summary-card.score {{
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        }}
        .summary-card.failed {{
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 1.2em;
        }}
        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #007acc;
            border-left: 4px solid #007acc;
            padding-left: 15px;
            margin-bottom: 20px;
        }}
        .test-grid {{
            display: grid;
            gap: 15px;
        }}
        .test-item {{
            background: #f8f9fa;
            border-left: 4px solid #28a745;
            padding: 15px;
            border-radius: 5px;
            transition: all 0.3s ease;
        }}
        .test-item:hover {{
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }}
        .test-item.failed {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        .test-item.error {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        .test-name {{
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        .test-result {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .test-result.passed {{
            background: #d4edda;
            color: #155724;
        }}
        .test-result.failed {{
            background: #f8d7da;
            color: #721c24;
        }}
        .test-result.error {{
            background: #fff3cd;
            color: #856404;
        }}
        .test-details {{
            margin-top: 10px;
            padding: 10px;
            background: white;
            border-radius: 5px;
            font-size: 0.9em;
        }}
        .system-status {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }}
        .service-card {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .service-card.healthy {{
            border-color: #28a745;
            background: #f8fff9;
        }}
        .service-card.unhealthy {{
            border-color: #dc3545;
            background: #fff5f5;
        }}
        .service-name {{
            font-weight: bold;
            font-size: 1.1em;
            margin-bottom: 10px;
        }}
        .service-status {{
            display: inline-block;
            padding: 6px 15px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        .service-status.healthy {{
            background: #d4edda;
            color: #155724;
        }}
        .service-status.unhealthy {{
            background: #f8d7da;
            color: #721c24;
        }}
        .response-time {{
            color: #666;
            font-size: 0.9em;
        }}
        .compliance-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
        }}
        .compliance-section {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
        }}
        .compliance-section h3 {{
            margin: 0 0 15px 0;
            color: #007acc;
        }}
        .compliance-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }}
        .compliance-item:last-child {{
            border-bottom: none;
        }}
        .compliance-status {{
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .compliance-status.compliant {{
            background: #d4edda;
            color: #155724;
        }}
        .compliance-status.protected {{
            background: #cce7ff;
            color: #004085;
        }}
        .compliance-status.monitored {{
            background: #fff3cd;
            color: #856404;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #666;
        }}
        .metadata {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .metadata-item {{
            display: inline-block;
            margin-right: 20px;
            margin-bottom: 5px;
        }}
        .metadata-label {{
            font-weight: bold;
            color: #007acc;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Zero Trust Security Test Results</h1>
            <div class="subtitle">Kapsamlı Güvenlik Değerlendirme Raporu</div>
        </div>

        <div class="metadata">
            <div class="metadata-item">
                <span class="metadata-label">Değerlendirme Tarihi:</span> 
                {self.data['test_metadata']['assessment_date'][:19].replace('T', ' ')}
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Sistem:</span> 
                {self.data['test_metadata']['system_name']}
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Versiyon:</span> 
                {self.data['test_metadata']['version']}
            </div>
            <div class="metadata-item">
                <span class="metadata-label">Değerlendiren:</span> 
                {self.data['test_metadata']['assessor']}
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card score">
                <h3>Genel Güvenlik Skoru</h3>
                <div class="value">{self.data['overall_score']}/100</div>
                <div>Başarı Oranı: {self.data['test_summary']['success_rate']}</div>
            </div>
            <div class="summary-card">
                <h3>Geçen Testler</h3>
                <div class="value">{self.data['test_summary']['passed_tests']}</div>
                <div>Toplam: {self.data['test_summary']['total_tests']}</div>
            </div>
            <div class="summary-card failed">
                <h3>Başarısız Testler</h3>
                <div class="value">{self.data['test_summary']['failed_tests']}</div>
                <div>Düzeltilmesi gerekenler</div>
            </div>
        </div>

        {self.generate_system_status()}
        {self.generate_security_tests()}
        {self.generate_compliance_section()}

        <div class="footer">
            <p>Bu rapor Zero Trust Security Assessment aracı tarafından otomatik olarak oluşturulmuştur.</p>
            <p>Rapor tarihi: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def generate_system_status(self):
        """Sistem durumu HTML'i oluştur"""
        html = """
        <div class="section">
            <h2>Sistem Durumu</h2>
            <div class="system-status">
"""
        
        for service_name, status in self.data['system_status'].items():
            status_class = status['status']
            response_time = status.get('response_time_ms', 0)
            
            html += f"""
                <div class="service-card {status_class}">
                    <div class="service-name">{service_name.title()}</div>
                    <div class="service-status {status_class}">{status['status'].title()}</div>
                    <div class="response-time">Yanıt Süresi: {response_time:.1f}ms</div>
                </div>
"""
        
        html += """
            </div>
        </div>
"""
        return html
    
    def generate_security_tests(self):
        """Güvenlik testleri HTML'i oluştur"""
        html = """
        <div class="section">
            <h2>Güvenlik Test Sonuçları</h2>
            <div class="test-grid">
"""
        
        for test_name, test_data in self.data['security_tests'].items():
            if isinstance(test_data, dict):
                result = test_data.get('result', test_data.get('overall_result', 'UNKNOWN'))
                result_class = result.lower() if result != 'UNKNOWN' else 'error'
                
                test_title = test_data.get('test', test_name.replace('_', ' ').title())
                
                html += f"""
                <div class="test-item {result_class}">
                    <div class="test-name">{test_title}</div>
                    <span class="test-result {result_class}">{result}</span>
"""
                
                # Test detayları
                if 'details' in test_data:
                    details = test_data['details']
                    if isinstance(details, str):
                        html += f'<div class="test-details">Detay: {details}</div>'
                    elif isinstance(details, dict):
                        html += '<div class="test-details">'
                        for key, value in details.items():
                            if key not in ['status', 'test_id', 'timestamp']:
                                html += f'<strong>{key}:</strong> {value}<br>'
                        html += '</div>'
                
                # Header testleri için özel gösterim
                if 'headers' in test_data:
                    html += '<div class="test-details"><strong>Security Headers:</strong><br>'
                    for header, header_data in test_data['headers'].items():
                        status_icon = "✅" if header_data['result'] == 'PASSED' else "❌"
                        html += f'{status_icon} {header}: {header_data["result"]}<br>'
                    html += '</div>'
                
                # Expected/Actual değerleri
                if 'expected' in test_data and 'actual' in test_data:
                    html += f"""
                    <div class="test-details">
                        <strong>Beklenen:</strong> {test_data['expected']}<br>
                        <strong>Gerçek:</strong> {test_data['actual']}
                    </div>
"""
                
                # Error mesajları
                if 'error' in test_data:
                    html += f'<div class="test-details"><strong>Hata:</strong> {test_data["error"]}</div>'
                
                html += '</div>'
        
        html += """
            </div>
        </div>
"""
        return html
    
    def generate_compliance_section(self):
        """Compliance bölümü HTML'i oluştur"""
        html = """
        <div class="section">
            <h2>Uyumluluk Değerlendirmesi</h2>
            <div class="compliance-grid">
"""
        
        # NIST Zero Trust
        if 'nist_zero_trust' in self.data['compliance_tests']:
            html += """
                <div class="compliance-section">
                    <h3>NIST Zero Trust Architecture</h3>
"""
            for item, status in self.data['compliance_tests']['nist_zero_trust'].items():
                status_class = status.lower()
                html += f"""
                    <div class="compliance-item">
                        <span>{item.replace('_', ' ').title()}</span>
                        <span class="compliance-status {status_class}">{status}</span>
                    </div>
"""
            html += '</div>'
        
        # OWASP Top 10
        if 'owasp_top_10' in self.data['compliance_tests']:
            html += """
                <div class="compliance-section">
                    <h3>OWASP Top 10 Compliance</h3>
"""
            for item, status in self.data['compliance_tests']['owasp_top_10'].items():
                status_class = status.lower()
                html += f"""
                    <div class="compliance-item">
                        <span>{item.replace('_', ' ').title()}</span>
                        <span class="compliance-status {status_class}">{status}</span>
                    </div>
"""
            html += '</div>'
        
        html += """
            </div>
        </div>
"""
        return html
    
    def save_html_report(self, output_file=None):
        """HTML raporunu kaydet"""
        if output_file is None:
            # JSON dosya adından HTML dosya adı oluştur
            json_path = Path(self.json_file)
            output_file = json_path.parent / f"{json_path.stem}_report.html"
        
        try:
            html_content = self.generate_html()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"HTML raporu oluşturuldu: {output_file}")
            return str(output_file)
            
        except Exception as e:
            print(f"HTML raporu oluşturulamadı: {e}")
            return None

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python generate_html_report.py <json_file>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    if not Path(json_file).exists():
        print(f"JSON dosyası bulunamadı: {json_file}")
        sys.exit(1)
    
    generator = HTMLReportGenerator(json_file)
    output_file = generator.save_html_report()
    
    if output_file:
        print(f"✅ HTML raporu başarıyla oluşturuldu!")
        print(f"📄 Dosya: {output_file}")
        print(f"🌐 Raporu görüntülemek için tarayıcıda açın.")
    else:
        print("❌ HTML raporu oluşturulamadı!")

if __name__ == "__main__":
    main()
