#!/usr/bin/env python3
"""
Test Sonuçları Özet Gösterici
Kaydedilen test sonuçlarının özetini gösterir
"""

import json
import sys

def show_test_summary(json_file):
    """Test sonuçları özetini göster"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print("🔒 Zero Trust Security Test Results Summary")
        print("=" * 50)
        
        # Temel bilgiler
        metadata = data.get('test_metadata', {})
        print(f"📅 Assessment Date: {metadata.get('assessment_date', 'N/A')}")
        print(f"🏢 System: {metadata.get('system_name', 'N/A')}")
        print(f"📊 Version: {metadata.get('version', 'N/A')}")
        print()
        
        # Test özeti
        summary = data.get('test_summary', {})
        print("📈 Test Summary:")
        print(f"   Total Tests: {summary.get('total_tests', 'N/A')}")
        print(f"   Passed: {summary.get('passed_tests', 'N/A')}")
        print(f"   Failed: {summary.get('failed_tests', 'N/A')}")
        print(f"   Success Rate: {summary.get('success_rate', 'N/A')}")
        print(f"   Overall Score: {data.get('overall_score', 'N/A')}/100")
        print()
        
        # Sistem durumu
        print("🖥️  System Status:")
        system_status = data.get('system_status', {})
        for service, status in system_status.items():
            status_emoji = "✅" if status.get('status') == 'healthy' else "❌"
            response_time = status.get('response_time_ms', 'N/A')
            print(f"   {status_emoji} {service}: {status.get('status', 'N/A')} ({response_time}ms)")
        print()
        
        # Güvenlik testleri
        print("🔐 Security Tests:")
        security_tests = data.get('security_tests', {})
        for test_name, test_data in security_tests.items():
            if isinstance(test_data, dict):
                result = test_data.get('result', 'N/A')
                result_emoji = "✅" if result == 'PASSED' else "❌" if result == 'FAILED' else "⚠️"
                print(f"   {result_emoji} {test_name}: {result}")
        print()
        
        # Compliance testleri
        print("📋 Compliance Status:")
        compliance = data.get('compliance_tests', {})
        
        if 'nist_zero_trust' in compliance:
            print("   NIST Zero Trust:")
            nist = compliance['nist_zero_trust']
            for area, status in nist.items():
                status_emoji = "✅" if status == 'COMPLIANT' else "❌"
                print(f"     {status_emoji} {area.replace('_', ' ').title()}: {status}")
        
        if 'owasp_top_10' in compliance:
            print("   OWASP Top 10:")
            owasp = compliance['owasp_top_10']
            for category, status in owasp.items():
                if status == 'NOT_APPLICABLE':
                    status_emoji = "⚪"
                elif status in ['PROTECTED', 'MONITORED']:
                    status_emoji = "✅"
                else:
                    status_emoji = "❌"
                print(f"     {status_emoji} {category.replace('_', ' ').title()}: {status}")
        print()
        
        # Dosya bilgileri
        print("📁 Generated Files:")
        print(f"   📄 JSON Report: {json_file}")
        html_file = json_file.replace('.json', '_report.html')
        print(f"   🌐 HTML Report: {html_file}")
        print()
        
        print("✨ Assessment completed successfully!")
        
    except Exception as e:
        print(f"❌ Error reading test results: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python show_test_summary.py <test_results.json>")
        sys.exit(1)
    
    show_test_summary(sys.argv[1])
