#!/usr/bin/env python3
"""
OWASP ZAP Headless Scanner for Next.js/SPA Applications
Handles authentication, session management, and AJAX spider
"""
import os
import sys
import time
import json
from zapv2 import ZAPv2

class NextJSZAPScanner:
    def __init__(self, target_url, api_key=None):
        self.target = target_url
        self.zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        
    def configure_spa_scanning(self):
        """Configure ZAP for SPA/Next.js scanning"""
        # Enable AJAX Spider for React/Next.js
        self.zap.ajaxSpider.set_option_max_duration('10')
        self.zap.ajaxSpider.set_option_number_of_browsers('2')
        
        # Configure modern browser
        self.zap.ajaxSpider.set_option_browser_id('firefox-headless')
        
        # Handle client-side routing
        self.zap.spider.set_option_max_depth(5)
        self.zap.spider.set_option_max_children(20)
        
        print("[+] SPA scanning configured")
    
    def authenticate(self, login_url, username, password, username_field='email', password_field='password'):
        """Handle Next.js authentication (JWT/cookies)"""
        # Set up authentication
        auth_method = self.zap.authentication.set_authentication_method(
            contextid='1',
            authmethodname='formBasedAuthentication',
            authmethodconfigparams=f'loginUrl={login_url}&loginRequestData={username_field}={username}&{password_field}={password}'
        )
        
        # Configure session management for Next.js
        self.zap.sessionManagement.set_session_management_method(
            contextid='1',
            methodname='cookieBasedSessionManagement'
        )
        
        print(f"[+] Authentication configured for {login_url}")
    
    def spider_scan(self):
        """Run traditional + AJAX spider"""
        print(f"[*] Starting spider on {self.target}")
        
        # Traditional spider
        scan_id = self.zap.spider.scan(self.target)
        while int(self.zap.spider.status(scan_id)) < 100:
            print(f"Spider progress: {self.zap.spider.status(scan_id)}%")
            time.sleep(2)
        
        # AJAX Spider for SPA
        print("[*] Starting AJAX spider for SPA routes")
        self.zap.ajaxSpider.scan(self.target)
        while self.zap.ajaxSpider.status == 'running':
            print(f"AJAX Spider running...")
            time.sleep(2)
        
        print("[+] Spidering complete")
    
    def active_scan(self):
        """Run active vulnerability scan"""
        print("[*] Starting active scan")
        scan_id = self.zap.ascan.scan(self.target)
        
        while int(self.zap.ascan.status(scan_id)) < 100:
            print(f"Scan progress: {self.zap.ascan.status(scan_id)}%")
            time.sleep(5)
        
        print("[+] Active scan complete")
    
    def generate_report(self, output_path='reports/zap-report.json'):
        """Generate comprehensive report"""
        alerts = self.zap.core.alerts(baseurl=self.target)
        
        report = {
            'target': self.target,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_alerts': len(alerts),
            'alerts_by_risk': {
                'High': len([a for a in alerts if a['risk'] == 'High']),
                'Medium': len([a for a in alerts if a['risk'] == 'Medium']),
                'Low': len([a for a in alerts if a['risk'] == 'Low']),
                'Informational': len([a for a in alerts if a['risk'] == 'Informational'])
            },
            'alerts': alerts
        }
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also generate HTML report
        html_report = self.zap.core.htmlreport()
        with open(output_path.replace('.json', '.html'), 'w') as f:
            f.write(html_report)
        
        print(f"[+] Reports saved to {output_path}")
        return report

def main():
    if len(sys.argv) < 2:
        print("Usage: python zap_scanner.py <target_url> [login_url] [username] [password]")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = NextJSZAPScanner(target)
    
    # Configure for SPA
    scanner.configure_spa_scanning()
    
    # Optional authentication
    if len(sys.argv) >= 5:
        scanner.authenticate(sys.argv[2], sys.argv[3], sys.argv[4])
    
    # Run scans
    scanner.spider_scan()
    scanner.active_scan()
    
    # Generate report
    report = scanner.generate_report()
    
    # Exit with error if high-risk issues found
    if report['alerts_by_risk']['High'] > 0:
        print(f"[!] Found {report['alerts_by_risk']['High']} high-risk vulnerabilities")
        sys.exit(1)
    
    print("[+] Security scan completed successfully")

if __name__ == '__main__':
    main()
