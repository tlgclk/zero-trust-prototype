"""
OWASP ZAP Integration for Zero Trust Security Testing
Advanced vulnerability scanning and penetration testing
"""

import os
import json
import time
import requests
import subprocess
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class ZAPSecurityTester:
    def __init__(self, zap_proxy="http://zap:8080"):
        self.zap_proxy = zap_proxy
        self.zap_api_key = os.getenv('ZAP_API_KEY', 'zero-trust-api-key')
        self.target_urls = [
            "http://user-service:5000",
            "http://admin-service:5000", 
            "http://security-test-service:5000"
        ]
        
    def wait_for_zap(self, timeout=60):
        """Wait for ZAP proxy to be ready"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{self.zap_proxy}/JSON/core/view/version/")
                if response.status_code == 200:
                    logger.info("ZAP proxy is ready")
                    return True
            except requests.exceptions.RequestException:
                time.sleep(2)
        
        logger.error("ZAP proxy not ready within timeout")
        return False
    
    def spider_scan(self, target_url: str) -> Dict:
        """Run ZAP spider scan"""
        try:
            # Start spider scan
            spider_url = f"{self.zap_proxy}/JSON/spider/action/scan/"
            spider_params = {
                'apikey': self.zap_api_key,
                'url': target_url,
                'maxChildren': '10',
                'recurse': 'true'
            }
            
            response = requests.get(spider_url, params=spider_params)
            scan_id = response.json().get('scan')
            
            if not scan_id:
                return {"status": "failed", "error": "Could not start spider scan"}
            
            # Wait for spider scan to complete
            while True:
                status_url = f"{self.zap_proxy}/JSON/spider/view/status/"
                status_params = {'apikey': self.zap_api_key, 'scanId': scan_id}
                status_response = requests.get(status_url, params=status_params)
                progress = int(status_response.json().get('status', 0))
                
                if progress >= 100:
                    break
                    
                time.sleep(2)
            
            # Get spider results
            results_url = f"{self.zap_proxy}/JSON/spider/view/results/"
            results_params = {'apikey': self.zap_api_key, 'scanId': scan_id}
            results_response = requests.get(results_url, params=results_params)
            
            return {
                "status": "success",
                "scan_id": scan_id,
                "urls_found": results_response.json().get('results', []),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Spider scan failed: {str(e)}")
            return {"status": "error", "error": str(e)}
    
    def active_scan(self, target_url: str) -> Dict:
        """Run ZAP active vulnerability scan"""
        try:
            # Start active scan
            scan_url = f"{self.zap_proxy}/JSON/ascan/action/scan/"
            scan_params = {
                'apikey': self.zap_api_key,
                'url': target_url,
                'recurse': 'true',
                'inScopeOnly': 'false'
            }
            
            response = requests.get(scan_url, params=scan_params)
            scan_id = response.json().get('scan')
            
            if not scan_id:
                return {"status": "failed", "error": "Could not start active scan"}
            
            # Wait for active scan to complete (with timeout)
            timeout = 300  # 5 minutes
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                status_url = f"{self.zap_proxy}/JSON/ascan/view/status/"
                status_params = {'apikey': self.zap_api_key, 'scanId': scan_id}
                status_response = requests.get(status_url, params=status_params)
                progress = int(status_response.json().get('status', 0))
                
                if progress >= 100:
                    break
                    
                time.sleep(5)
            
            return {
                "status": "success",
                "scan_id": scan_id,
                "progress": progress,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Active scan failed: {str(e)}")
            return {"status": "error", "error": str(e)}
    
    def get_alerts(self, risk_level: str = "High") -> Dict:
        """Get security alerts from ZAP"""
        try:
            alerts_url = f"{self.zap_proxy}/JSON/core/view/alerts/"
            alerts_params = {
                'apikey': self.zap_api_key,
                'baseurl': '',
                'start': '0',
                'count': '100',
                'riskId': self._get_risk_id(risk_level)
            }
            
            response = requests.get(alerts_url, params=alerts_params)
            alerts = response.json().get('alerts', [])
            
            # Process and categorize alerts
            categorized_alerts = {
                "High": [],
                "Medium": [],
                "Low": [],
                "Informational": []
            }
            
            for alert in alerts:
                risk = alert.get('risk', 'Low')
                categorized_alerts[risk].append({
                    "name": alert.get('alert', ''),
                    "description": alert.get('description', ''),
                    "solution": alert.get('solution', ''),
                    "reference": alert.get('reference', ''),
                    "url": alert.get('url', ''),
                    "param": alert.get('param', ''),
                    "evidence": alert.get('evidence', '')
                })
            
            return {
                "status": "success",
                "alerts": categorized_alerts,
                "total_alerts": len(alerts),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get alerts: {str(e)}")
            return {"status": "error", "error": str(e)}
    
    def _get_risk_id(self, risk_level: str) -> str:
        """Convert risk level to ZAP risk ID"""
        risk_mapping = {
            "High": "3",
            "Medium": "2", 
            "Low": "1",
            "Informational": "0"
        }
        return risk_mapping.get(risk_level, "")
    
    def run_comprehensive_scan(self, target_url: str) -> Dict:
        """Run comprehensive security scan"""
        results = {
            "target_url": target_url,
            "start_time": datetime.utcnow().isoformat(),
            "tests": {}
        }
        
        # 1. Spider scan
        logger.info(f"Starting spider scan for {target_url}")
        spider_result = self.spider_scan(target_url)
        results["tests"]["spider_scan"] = spider_result
        
        # 2. Active scan
        logger.info(f"Starting active scan for {target_url}")
        active_result = self.active_scan(target_url)
        results["tests"]["active_scan"] = active_result
        
        # 3. Get alerts
        logger.info(f"Retrieving security alerts for {target_url}")
        alerts_result = self.get_alerts()
        results["tests"]["security_alerts"] = alerts_result
        
        results["end_time"] = datetime.utcnow().isoformat()
        results["status"] = "completed"
        
        return results
    
    def run_all_targets(self) -> Dict:
        """Run security tests against all target services"""
        if not self.wait_for_zap():
            return {"status": "failed", "error": "ZAP proxy not available"}
        
        all_results = {
            "test_type": "OWASP ZAP Comprehensive Scan",
            "start_time": datetime.utcnow().isoformat(),
            "targets": {}
        }
        
        for target_url in self.target_urls:
            service_name = target_url.split('://')[1].split(':')[0]
            logger.info(f"Scanning service: {service_name}")
            
            all_results["targets"][service_name] = self.run_comprehensive_scan(target_url)
        
        all_results["end_time"] = datetime.utcnow().isoformat()
        all_results["total_targets"] = len(self.target_urls)
        
        return all_results
    
    def generate_security_report(self) -> Dict:
        """Generate comprehensive security report"""
        scan_results = self.run_all_targets()
        
        # Analyze results and generate recommendations
        recommendations = []
        critical_issues = 0
        
        for service, results in scan_results.get("targets", {}).items():
            alerts = results.get("tests", {}).get("security_alerts", {}).get("alerts", {})
            
            high_alerts = len(alerts.get("High", []))
            medium_alerts = len(alerts.get("Medium", []))
            
            critical_issues += high_alerts
            
            if high_alerts > 0:
                recommendations.append(f"Address {high_alerts} high-risk vulnerabilities in {service}")
            
            if medium_alerts > 3:
                recommendations.append(f"Review {medium_alerts} medium-risk issues in {service}")
        
        # Generate overall security score
        security_score = max(0, 100 - (critical_issues * 20) - (len(recommendations) * 5))
        
        report = {
            "security_assessment": {
                "overall_score": security_score,
                "risk_level": self._get_risk_level(security_score),
                "critical_issues": critical_issues,
                "recommendations": recommendations
            },
            "detailed_results": scan_results,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        return report
    
    def _get_risk_level(self, score: int) -> str:
        """Determine risk level based on security score"""
        if score >= 90:
            return "LOW"
        elif score >= 70:
            return "MEDIUM"
        elif score >= 50:
            return "HIGH"
        else:
            return "CRITICAL"
