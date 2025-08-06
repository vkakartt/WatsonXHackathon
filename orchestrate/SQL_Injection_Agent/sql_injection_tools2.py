#!/usr/bin/env python3
"""
Ultra-Fast SQL Injection Scanner
Combines multiple fast techniques to detect SQL injection in under 30 seconds
"""

import requests
import subprocess
import re
import concurrent.futures
import time
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import json

class FastSQLScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.timeout = 5
        
    def quick_endpoint_discovery(self, url, max_time=10):
        """Fast endpoint discovery - completes in ~10 seconds"""
        print(f"[*] Quick endpoint discovery for: {url}")
        start_time = time.time()
        endpoints = []
        
        try:
            # Get main page
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract form actions (fastest method)
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    full_url = urljoin(url, action)
                    method = form.get('method', 'GET').upper()
                    
                    # Extract form fields
                    fields = {}
                    for input_field in form.find_all(['input', 'textarea']):
                        name = input_field.get('name')
                        if name:
                            if input_field.get('type') == 'password':
                                fields[name] = 'test123'
                            elif name.lower() in ['username', 'user', 'email', 'login']:
                                fields[name] = 'admin'
                            else:
                                fields[name] = 'test'
                    
                    endpoints.append({
                        'url': full_url,
                        'method': method,
                        'data': fields,
                        'type': 'form'
                    })
            
            # Quick JavaScript scan (only inline scripts for speed)
            for script in soup.find_all('script', src=False):
                if script.string and time.time() - start_time < max_time:
                    js_endpoints = self.extract_js_endpoints(script.string, url)
                    endpoints.extend(js_endpoints)
            
            # Test common endpoints (parallel for speed)
            base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            common_paths = ['/api/login', '/login', '/auth', '/api/auth', '/signin']
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_path = {
                    executor.submit(self.test_endpoint_exists, base_url + path): path 
                    for path in common_paths
                }
                
                for future in concurrent.futures.as_completed(future_to_path, timeout=5):
                    path = future_to_path[future]
                    try:
                        if future.result():
                            endpoints.append({
                                'url': base_url + path,
                                'method': 'POST',
                                'data': {'username': 'admin', 'password': 'test123'},
                                'type': 'common'
                            })
                    except:
                        continue
            
        except Exception as e:
            print(f"[-] Discovery error: {e}")
        
        print(f"[+] Found {len(endpoints)} endpoints in {time.time()-start_time:.1f}s")
        return endpoints
    
    def extract_js_endpoints(self, js_content, base_url):
        """Quick JavaScript endpoint extraction"""
        endpoints = []
        patterns = [
            r'["\']https?://[^"\']*(?:login|auth|api)[^"\']*["\']',
            r'["\'][^"\']*(?:/login|/auth|/api)[^"\']*["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                endpoint = match.strip('\'"')
                if endpoint.startswith('/'):
                    endpoint = urljoin(base_url, endpoint)
                endpoints.append({
                    'url': endpoint,
                    'method': 'POST',
                    'data': {'username': 'admin', 'password': 'test123'},
                    'type': 'js'
                })
        
        return endpoints
    
    def test_endpoint_exists(self, url):
        """Quick endpoint existence test"""
        try:
            response = self.session.head(url, timeout=2)
            return response.status_code not in [404, 403]
        except:
            return False
    
    def fast_sqlmap_test(self, endpoint):
        """Ultra-fast sqlmap test - 5-10 seconds per endpoint"""
        url = endpoint['url']
        method = endpoint['method']
        data = endpoint.get('data', {})
        
        # Build minimal sqlmap command for speed
        cmd = [
            'sqlmap',
            '-u', url,
            '--batch',
            '--technique', 'B',  # Only boolean-based (fastest)
            '--level', '1',      # Minimal level
            '--risk', '1',       # Minimal risk
            '--timeout', '3',    # 3 second timeout
            '--retries', '1',    # Only 1 retry
            '--threads', '3',    # Parallel threads
            '--quiet'            # Minimal output
        ]
        
        if method == 'POST' and data:
            form_data = '&'.join([f"{k}={v}" for k, v in data.items()])
            cmd.extend(['--data', form_data])
        
        print(f"[*] Testing: {url}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            # Check for vulnerability indicators
            output = result.stdout.lower()
            if any(indicator in output for indicator in ['injectable', 'parameter', 'payload']):
                return {
                    'url': url,
                    'vulnerable': True,
                    'method': method,
                    'data': data,
                    'evidence': result.stdout
                }
            
        except subprocess.TimeoutExpired:
            print(f"[-] Timeout: {url}")
        except Exception as e:
            print(f"[-] Error: {url} - {e}")
        
        return {'url': url, 'vulnerable': False}
    
    def manual_sql_test(self, endpoint):
        """Quick manual SQL injection test - 2-3 seconds"""
        url = endpoint['url']
        method = endpoint['method']
        data = endpoint.get('data', {})
        
        if not data:
            return {'url': url, 'vulnerable': False, 'method': 'manual'}
        
        # Quick SQL payloads
        payloads = ["'", "' OR '1'='1", "admin'--"]
        
        original_response = None
        vulnerable_responses = []
        
        try:
            # Get baseline response
            if method == 'POST':
                original_response = self.session.post(url, data=data, timeout=3)
            else:
                original_response = self.session.get(url, params=data, timeout=3)
            
            # Test each payload
            for payload in payloads:
                test_data = data.copy()
                # Inject into first parameter (usually username)
                first_param = list(test_data.keys())[0]
                test_data[first_param] = payload
                
                try:
                    if method == 'POST':
                        test_response = self.session.post(url, data=test_data, timeout=3)
                    else:
                        test_response = self.session.get(url, params=test_data, timeout=3)
                    
                    # Check for SQL error indicators
                    error_indicators = [
                        'sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite',
                        'syntax error', 'unexpected token', 'quoted string',
                        'unterminated', 'database error'
                    ]
                    
                    response_text = test_response.text.lower()
                    if any(indicator in response_text for indicator in error_indicators):
                        vulnerable_responses.append({
                            'payload': payload,
                            'response_length': len(test_response.text),
                            'status_code': test_response.status_code
                        })
                
                except:
                    continue
            
            if vulnerable_responses:
                return {
                    'url': url,
                    'vulnerable': True,
                    'method': 'manual',
                    'evidence': vulnerable_responses
                }
                
        except Exception as e:
            pass
        
        return {'url': url, 'vulnerable': False, 'method': 'manual'}
    
    def parallel_test_endpoints(self, endpoints, use_sqlmap=True):
        """Test multiple endpoints in parallel for maximum speed"""
        print(f"[*] Testing {len(endpoints)} endpoints in parallel...")
        
        vulnerable_endpoints = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            if use_sqlmap:
                # Use sqlmap for more thorough testing
                futures = [executor.submit(self.fast_sqlmap_test, endpoint) for endpoint in endpoints]
            else:
                # Use manual testing for maximum speed
                futures = [executor.submit(self.manual_sql_test, endpoint) for endpoint in endpoints]
            
            for future in concurrent.futures.as_completed(futures, timeout=30):
                try:
                    result = future.result()
                    if result.get('vulnerable'):
                        vulnerable_endpoints.append(result)
                except Exception as e:
                    print(f"[-] Test error: {e}")
        
        return vulnerable_endpoints
    
    def ultra_fast_scan(self, target_url, use_sqlmap=True):
        """Complete scan in under 30 seconds"""
        print(f"[*] Ultra-fast SQL injection scan: {target_url}")
        start_time = time.time()
        
        # Step 1: Quick endpoint discovery (10 seconds max)
        endpoints = self.quick_endpoint_discovery(target_url, max_time=10)
        
        if not endpoints:
            print("[-] No endpoints found to test")
            return []
        
        # Step 2: Parallel testing (15 seconds max)
        vulnerable = self.parallel_test_endpoints(endpoints, use_sqlmap)
        
        total_time = time.time() - start_time
        
        # Results
        print(f"\n{'='*50}")
        print(f"SCAN COMPLETED in {total_time:.1f} seconds")
        print(f"{'='*50}")
        print(f"Endpoints tested: {len(endpoints)}")
        print(f"Vulnerabilities found: {len(vulnerable)}")
        
        if vulnerable:
            print(f"\n🚨 VULNERABLE ENDPOINTS:")
            for vuln in vulnerable:
                print(f"  [!] {vuln['url']}")
                if vuln.get('evidence'):
                    print(f"      Method: {vuln.get('method', 'unknown')}")
                    if isinstance(vuln['evidence'], list):
                        for evidence in vuln['evidence'][:2]:  # Show first 2 pieces of evidence
                            print(f"      Payload: {evidence.get('payload', 'N/A')}")
        else:
            print("\n✅ No SQL injection vulnerabilities detected")
        
        return vulnerable

def main():
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 fast_sql_scanner.py <target_url>")
        print("Example: python3 fast_sql_scanner.py https://example.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = FastSQLScanner()
    
    # Ultra-fast scan with sqlmap
    print("=== ULTRA-FAST SCAN WITH SQLMAP ===")
    results_sqlmap = scanner.ultra_fast_scan(target_url, use_sqlmap=True)
    
    # If no results and want even faster, try manual method
    if not results_sqlmap:
        print("\n=== BACKUP: MANUAL TESTING (FASTEST) ===")
        endpoints = scanner.quick_endpoint_discovery(target_url, max_time=5)
        results_manual = scanner.parallel_test_endpoints(endpoints, use_sqlmap=False)
        
        if results_manual:
            print(f"Manual testing found {len(results_manual)} potential vulnerabilities")

if __name__ == "__main__":
    main()