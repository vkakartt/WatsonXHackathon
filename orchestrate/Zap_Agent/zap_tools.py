import subprocess
import time
import os
import requests
from zapv2 import ZAPv2
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
from typing import List
import threading

class FastVulnScanner:
    def __init__(self, zap_port=8090, api_key="12345"):
        self.zap_port = zap_port
        self.api_key = api_key
        self.zap_api_url = "https://kxhmqxrn-8000.use.devtunnels.ms/zap"
        self.zap = None
        self.zap_process = None

    def is_zap_running(self):
        try:
            response = requests.get(f"{self.zap_api_url}/JSON/core/view/version/", timeout=3)
            return response.status_code == 200
        except:
            return False
        
    def zap_get(self, path, params=None):
        if params is None:
            params = {}
        resp = requests.get(f"{self.zap_api_url}{path}", params=params)
        resp.raise_for_status()
        return resp.json()

    def zap_post(self, path, data=None):
        if data is None:
            data = {}
        resp = requests.post(f"{self.zap_api_url}{path}", data=data)
        resp.raise_for_status()
        return resp.json()

    
    def quick_spider(self, target_url: str, max_time=30):
        print(f"[*] Quick spidering {target_url} (max {max_time}s)...")

        self.zap_get("/JSON/spider/action/setOptionMaxDepth", {"Integer": 2})
        self.zap_get("/JSON/spider/action/setOptionMaxChildren", {"Integer": 10})
        self.zap_get("/JSON/spider/action/setOptionMaxDuration", {"Integer": max_time})

        spider_id = self.zap_get("/JSON/spider/action/scan/", {"url": target_url})["scan"]

        start_time = time.time()
        while time.time() - start_time < max_time:
            status = int(self.zap_get("/JSON/spider/view/status/", {"scanId": spider_id})["status"])
            if status >= 100:
                break
            time.sleep(2)

        self.zap_get("/JSON/spider/action/stop/", {"scanId": spider_id})
        urls = self.zap_get("/JSON/core/view/urls/", {"baseurl": target_url})["urls"]
        print(f"[*] Found {len(urls)} URLs in {int(time.time() - start_time)}s")
        return urls

    def fast_active_scan(self, target_url: str, scan_types: List[str] = None, max_time=60):
        print(f"[*] Running fast active scan (max {max_time}s)...")

        self.zap_get("/JSON/ascan/action/disableAllScanners/")
        self.zap_get("/JSON/pscan/action/disableAllScanners/")
        self.zap_get("/JSON/pscan/action/setEnabled/", {"enabled": "false"})

        scanner_map = {
            'sql_injection': ['40018', '40019', '40020', '40021', '40022', '40024', '40027'],
            'xss': ['40012', '40014', '40016', '40017', '40026'],
            'lfi': ['40003'],
            'rfi': ['7'],
            'xxe': ['90021'],
            'directory_traversal': ['6'],
            'command_injection': ['90020'],
            'xpath_injection': ['90021']
        }

        if not scan_types:
            scan_types = ['xss', 'lfi', 'sql_injection']

        scanner_ids = []
        enabled_count = 0
        for scan_type in scan_types:
            if scan_type in scanner_map:
                scanner_ids = scanner_map[scan_type]  # This is a list of scanner IDs
                
                print(",".join(scanner_ids))
                
                # Enable all scanners in one API call (comma-separated string)
                self.zap_get("/JSON/ascan/action/enableScanners/", {
                    "ids": ",".join(scanner_ids)
                })
                
                # For each scanner ID, set attack strength and alert threshold
                enabled_count += len(scanner_ids)


        print(f"[*] Enabled {enabled_count} scanners for: {', '.join(scan_types)}")

        scan_id = self.zap_get("/JSON/ascan/action/scan/", {"url": target_url})["scan"]

        start_time = time.time()
        while time.time() - start_time < max_time:
            status = int(self.zap_get("/JSON/ascan/view/status/", {"scanId": scan_id})["status"])
            if status >= 100:
                break
            time.sleep(3)

        self.zap_get("/JSON/ascan/action/stop/", {"scanId": scan_id})
        alerts = self.zap_get("/JSON/core/view/alerts/", {"baseurl": target_url})["alerts"]
        print(f"[*] Found {len(alerts)} alerts in {int(time.time() - start_time)}s")
        return alerts

# Main scanning functions
@tool(name="zap_active_scan", description="Preforms an in-depth active scan on the website target_url, scanning for scan_types vulnerabilties (between sql_injection (sql injection), xss (cross-site scripting), lfi (local file inclusion), rfi (remote file inclusion), xxe (xml external entity injection), csrf (cross-site request forgery), directory_traversal (directory traversal), command_injection (command injection), ldap_injection (LDAP injection), xpath_injection (xpath injection))", permission=ToolPermission.ADMIN)
def fast_comprehensive_scan(target_url: str, scan_types: List[str] = None):
    """
    Fast vulnerability scanner with multiple options
    
    Args:
        target_url: URL to scan
        scan_types: List of vulnerability types ['sql_injection', 'xss', 'lfi', 'rfi', 'xxe', 'csrf', 'directory_traversal', 'command_injection', 'ldap_injection', 'xpath_injection']
    """
        
    results = {
        'zap_results': [],
        'scan_time': 0
    }
    
    start_time = time.time()
    
    try:
        # ZAP Fast Scan
        print("=== ZAP Fast Scan ===")
        scanner = FastVulnScanner()
        if not scanner.is_zap_running():
            return "cringe"
        
        # Quick spider
        urls = scanner.quick_spider(target_url, max_time=15)
        
        # Fast active scan
        alerts = scanner.fast_active_scan(target_url, scan_types, max_time=45)
        results['zap_results'] = alerts
        
        results['scan_time'] = time.time() - start_time
        results['urls'] = urls
        
        # Summary
        total_issues = len(results['zap_results'])
        print(f"\n=== Scan Complete ===")
        print(f"Total time: {results['scan_time']:.1f}s")
        print(f"Total issues found: {total_issues}")
        print(f"ZAP alerts: {len(results['zap_results'])}")
        
        return results
        
    except Exception as e:
        print(f"[!] Scan error: {e}")
        results['error'] = str(e)
        return results
    
@tool(name="zap_passive_scan", description="Preforms a safe passive scan on the website target_url to determine preliminary security vulnerabilities.", permission=ToolPermission.ADMIN)
def passive_zap_scan(target_url: str) -> List[dict[str, str]]:
    try:
        scanner = FastVulnScanner()

        # Enable passive scan
        scanner.zap_get("/JSON/pscan/action/enableAllScanners/")
        scanner.zap_get("/JSON/pscan/action/setEnabled/", {"enabled": "true"})

        # Access the target to trigger passive scan
        scanner.zap_get("/JSON/core/action/accessUrl/", {"url": target_url})

        # Wait for passive scanner to finish
        while True:
            records_left = int(scanner.zap_get("/JSON/pscan/view/recordsToScan/")["recordsToScan"])
            print(f"Remaining records to scan: {records_left}")
            if records_left == 0:
                break
            time.sleep(2)

        # Fetch alerts
        alerts = scanner.zap_get("/JSON/core/view/alerts/", {"baseurl": target_url})["alerts"]
        print("[*] Passive scan complete.")
        return alerts

    except Exception as e:
        print(f"[!] Passive scan error: {e}")
        return [{"error": str(e)}]
    

@tool(name="screen_for_xss", description="Runs in depth xss specific zap tests on a given website.", permission=ToolPermission.ADMIN)
def screen_for_xss(website_link: str) -> str:
    output = ''
    try:
        scanner = FastVulnScanner()
        target = website_link

        # Access + Spider
        scanner.zap_get("/JSON/core/action/accessUrl/", {"url": target})
        scanner.zap_get("/JSON/spider/action/scan/", {"url": target})
        time.sleep(5)  # Optional: give spider a moment to run

        # Disable all scanners, then enable only XSS ones
        scanner.zap_get("/JSON/ascan/action/disableAllScanners/")
        scanner.zap_get("/JSON/ascan/action/enableScanners/", {"ids": "40012,40014,40016,40017"})

        # Start active scan
        scan_id = scanner.zap_get("/JSON/ascan/action/scan/", {"url": target})["scan"]

        # Wait for scan to complete (optional: you can add a timeout if needed)
        while True:
            status = int(scanner.zap_get("/JSON/ascan/view/status/", {"scanId": scan_id})["status"])
            print(f"XSS scan progress: {status}%")
            if status >= 100:
                break
            time.sleep(3)

        # Fetch alerts
        alerts = scanner.zap_get("/JSON/core/view/alerts/", {"baseurl": target})["alerts"]
        output += "[*] XSS Alerts:\n"
        bNoAlerts = True
        for alert in alerts:
            if 'xss' in alert['alert'].lower():
                output += f"- {alert['alert']} at {alert['url']}\n"
                bNoAlerts = False

        if bNoAlerts:
            output += "No XSS Vulnerabilities detected"

        return output

    except Exception as e:
        return f"[!] XSS scan error: {e}"

print(fast_comprehensive_scan("https://www.transformatech.com"))