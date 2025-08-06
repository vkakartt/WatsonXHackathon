import subprocess
import time
import os
import requests
import threading
import concurrent.futures
from zapv2 import ZAPv2
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission
import json
from typing import List, Dict, Optional
import tempfile

class FastVulnScanner:
    def __init__(self, zap_port=8090, api_key=""):
        self.zap_port = zap_port
        self.api_key = api_key
        self.zap_api_url = f"http://127.0.0.1:{zap_port}"
        self.zap = None
        self.zap_process = None

    def is_zap_running(self):
        try:
            response = requests.get(f"{self.zap_api_url}/JSON/core/view/version/", timeout=2)
            return response.status_code == 200
        except:
            return False

    def start_zap_fast(self):
        """Start ZAP with optimized settings for speed"""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        zap_path = os.path.join(base_dir, "ZAP_2.16.1/zap.bat")
        
        if not self.is_zap_running():
            print("[*] Starting ZAP in fast mode...")
            
            # Kill existing processes
            try:
                subprocess.run(["taskkill", "/F", "/IM", "java.exe"], 
                             capture_output=True, timeout=5)
                time.sleep(1)
            except:
                pass

            # Start ZAP with speed-optimized settings
            self.zap_process = subprocess.Popen([
                zap_path,
                "-daemon",
                "-port",
                str(self.zap_port),
                "-host",
                "127.0.0.1",
                "-config",
                "api=12345"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Wait for ZAP with shorter timeout
            for _ in range(30):  # 30 second timeout
                if self.is_zap_running():
                    break
                time.sleep(1)
            else:
                raise RuntimeError("ZAP failed to start quickly")
        
        self.zap = ZAPv2(apikey=self.api_key, proxies={
            'http': self.zap_api_url,
            'https': self.zap_api_url
        })
        return True

    def quick_spider(self, target_url: str, max_time=30):
        """Fast spider with time limits"""
        print(f"[*] Quick spidering {target_url} (max {max_time}s)...")
        
        # Configure spider for speed
        self.zap.spider.set_option_max_depth(2)
        self.zap.spider.set_option_max_children(10)
        self.zap.spider.set_option_max_duration(max_time)
        
        spider_id = self.zap.spider.scan(target_url)
        
        # Monitor with timeout
        start_time = time.time()
        while time.time() - start_time < max_time:
            status = int(self.zap.spider.status(spider_id))
            if status >= 100:
                break
            time.sleep(2)
        
        # Stop spider if still running
        self.zap.spider.stop(spider_id)
        urls = self.zap.core.urls(baseurl=target_url)
        print(f"[*] Found {len(urls)} URLs in {int(time.time() - start_time)}s")
        return urls

    def fast_active_scan(self, target_url: str, scan_types: List[str] = None, max_time=60):
        """Fast active scan with selective vulnerability types"""
        print(f"[*] Running fast active scan (max {max_time}s)...")
        
        # Disable all scanners first
        self.zap.ascan.disable_all_scanners()
        
        # Enable only requested vulnerability types
        scanner_map = {
            'sql_injection': ['40018', '40019', '40020', '40021', '40022'],
            'xss': ['40012', '40013', '40014', '40016', '40017'],
            'lfi': ['40003', '40004'],
            'rfi': ['40005'],
            'xxe': ['90021'],
            'csrf': ['20012'],
            'directory_traversal': ['40001', '40002'],
            'command_injection': ['90020'],
            'ldap_injection': ['40015'],
            'xpath_injection': ['40023']
        }
        
        if not scan_types:
            scan_types = ['sql_injection', 'xss', 'lfi']  # Default fast scan
        
        enabled_count = 0
        for scan_type in scan_types:
            if scan_type in scanner_map:
                for scanner_id in scanner_map[scan_type]:
                    try:
                        self.zap.ascan.enable_scanners(scanner_id)
                        self.zap.ascan.set_scanner_attack_strength(scanner_id, 'MEDIUM')
                        self.zap.ascan.set_scanner_alert_threshold(scanner_id, 'MEDIUM')
                        enabled_count += 1
                    except:
                        pass
        
        print(f"[*] Enabled {enabled_count} scanners for: {', '.join(scan_types)}")
        
        # Start scan
        scan_id = self.zap.ascan.scan(target_url)
        
        # Monitor with timeout
        start_time = time.time()
        while time.time() - start_time < max_time:
            status = int(self.zap.ascan.status(scan_id))
            if status >= 100:
                break
            time.sleep(3)
        
        # Stop scan if still running
        self.zap.ascan.stop(scan_id)
        
        alerts = self.zap.core.alerts(baseurl=target_url)
        print(f"[*] Found {len(alerts)} alerts in {int(time.time() - start_time)}s")
        return alerts

    def parallel_quick_scan(self, urls: List[str], scan_types: List[str] = None):
        """Run multiple quick scans in parallel"""
        results = {}
        
        def scan_single_url(url):
            try:
                alerts = self.fast_active_scan(url, scan_types, max_time=30)
                return url, alerts
            except Exception as e:
                print(f"[!] Error scanning {url}: {e}")
                return url, []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_url = {executor.submit(scan_single_url, url): url for url in urls[:5]}  # Limit to 5 URLs
            
            for future in concurrent.futures.as_completed(future_to_url):
                url, alerts = future.result()
                results[url] = alerts
        
        return results

# Alternative tools for faster scanning
class AlternativeScanner:
    """Alternative fast vulnerability scanners"""
    
    @staticmethod
    def run_nuclei(target_url: str, templates: List[str] = None):
        """Use Nuclei for fast vulnerability scanning"""
        if not templates:
            templates = ['sqli', 'xss', 'lfi', 'rfi', 'xxe']
        
        cmd = [
            'nuclei',
            '-u', target_url,
            '-t', ','.join([f'vulnerabilities/{t}' for t in templates]),
            '-json',
            '-timeout', '10',
            '-retries', '1',
            '-rate-limit', '50'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                results = []
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            results.append(json.loads(line))
                        except:
                            pass
                return results
            else:
                print(f"[!] Nuclei error: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print("[!] Nuclei scan timed out")
            return []
        except FileNotFoundError:
            print("[!] Nuclei not found. Install from: https://github.com/projectdiscovery/nuclei")
            return []

    @staticmethod
    def run_sqlmap_quick(target_url: str):
        """Quick SQLMap scan"""
        cmd = [
            'sqlmap',
            '-u', target_url,
            '--batch',
            '--random-agent',
            '--timeout=10',
            '--retries=1',
            '--threads=5',
            '--technique=BEU',  # Boolean, Error, Union based
            '--level=1',
            '--risk=1',
            '--format=JSON'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.stdout if result.returncode == 0 else None
        except:
            return None

# Main scanning functions
@tool(name="fast_vuln_scan", description="Fast comprehensive vulnerability scan", permission=ToolPermission.ADMIN)
def fast_comprehensive_scan(target_url: str, scan_types: List[str] = None, use_alternatives: bool = True):
    """
    Fast vulnerability scanner with multiple options
    
    Args:
        target_url: URL to scan
        scan_types: List of vulnerability types ['sql_injection', 'xss', 'lfi', 'rfi', 'xxe', 'csrf']
        use_alternatives: Whether to use alternative tools like Nuclei
    """
    
    if not scan_types:
        scan_types = ['sql_injection', 'xss', 'lfi', 'csrf']
    
    results = {
        'target': target_url,
        'scan_types': scan_types,
        'zap_results': [],
        'nuclei_results': [],
        'sqlmap_results': None,
        'scan_time': 0
    }
    
    start_time = time.time()
    
    try:
        # ZAP Fast Scan
        print("=== ZAP Fast Scan ===")
        scanner = FastVulnScanner()
        scanner.start_zap_fast()
        
        # Quick spider
        urls = scanner.quick_spider(target_url, max_time=15)
        
        # Fast active scan
        alerts = scanner.fast_active_scan(target_url, scan_types, max_time=45)
        results['zap_results'] = alerts
        
        # Alternative tools if requested
        if use_alternatives:
            print("\n=== Alternative Tools ===")
            
            # Nuclei scan
            nuclei_results = AlternativeScanner.run_nuclei(target_url, scan_types)
            results['nuclei_results'] = nuclei_results
            
            # Quick SQLMap for SQL injection
            if 'sql_injection' in scan_types:
                sqlmap_results = AlternativeScanner.run_sqlmap_quick(target_url)
                results['sqlmap_results'] = sqlmap_results
        
        results['scan_time'] = time.time() - start_time
        
        # Summary
        total_issues = len(results['zap_results']) + len(results['nuclei_results'] or [])
        print(f"\n=== Scan Complete ===")
        print(f"Total time: {results['scan_time']:.1f}s")
        print(f"Total issues found: {total_issues}")
        print(f"ZAP alerts: {len(results['zap_results'])}")
        print(f"Nuclei alerts: {len(results['nuclei_results'] or [])}")
        
        return results
        
    except Exception as e:
        print(f"[!] Scan error: {e}")
        results['error'] = str(e)
        return results

@tool(name="ultra_fast_scan", description="Ultra-fast 30-second vulnerability scan", permission=ToolPermission.ADMIN)
def ultra_fast_scan(target_url: str):
    """Ultra-fast scan in under 30 seconds"""
    print("=== Ultra Fast Scan (30s max) ===")
    
    start_time = time.time()
    results = []
    
    # Parallel execution of different scanners
    def zap_quick():
        try:
            scanner = FastVulnScanner()
            scanner.start_zap_fast()
            return scanner.fast_active_scan(target_url, ['sql_injection', 'xss'], max_time=20)
        except:
            return []
    
    def nuclei_quick():
        return AlternativeScanner.run_nuclei(target_url, ['sqli', 'xss'])
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        zap_future = executor.submit(zap_quick)
        nuclei_future = executor.submit(nuclei_quick)
        
        # Get results with timeout
        try:
            zap_results = zap_future.result(timeout=25)
            nuclei_results = nuclei_future.result(timeout=25)
        except concurrent.futures.TimeoutError:
            print("[!] Some scans timed out")
            zap_results = []
            nuclei_results = []
    
    total_time = time.time() - start_time
    total_issues = len(zap_results) + len(nuclei_results or [])
    
    print(f"\n✅ Ultra-fast scan complete in {total_time:.1f}s")
    print(f"Found {total_issues} potential issues")
    
    return {
        'target': target_url,
        'zap_results': zap_results,
        'nuclei_results': nuclei_results,
        'scan_time': total_time,
        'total_issues': total_issues
    }

# Usage examples
def main():
    target = "https://www.transformatech.com"
    
    print("Choose scanning mode:")
    print("1. Fast comprehensive scan (1-2 minutes)")
    print("2. Ultra-fast scan (30 seconds)")
    print("3. Custom scan types")
    
    choice = input("Enter choice (1-3): ").strip()
    
    if choice == "1":
        results = fast_comprehensive_scan(target)
    elif choice == "2":
        results = ultra_fast_scan(target)
    elif choice == "3":
        scan_types = input("Enter scan types (comma-separated): ").split(',')
        scan_types = [t.strip() for t in scan_types]
        results = fast_comprehensive_scan(target, scan_types)
    else:
        print("Invalid choice")
        return
    
    print(f"\nResults: {json.dumps(results, indent=2, default=str)}")

if __name__ == "__main__":
    main()