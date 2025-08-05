import os
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import subprocess
import sys
import json
from ibm_watsonx_orchestrate.agent_builder.tools import tool, ToolPermission

class StaticBackendDiscovery:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.result = ""
    
    def discover_from_html(self, url):
        """Discover endpoints from HTML source"""
        self.result += f"[+] Analyzing HTML source: {url}"
        endpoints = []
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find form actions
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action')
                if action:
                    full_url = urljoin(url, action)
                    method = form.get('method', 'GET').upper()
                    
                    # Extract form fields
                    fields = {}
                    for input_field in form.find_all(['input', 'textarea', 'select']):
                        name = input_field.get('name')
                        if name:
                            field_type = input_field.get('type', 'text')
                            if field_type == 'password':
                                fields[name] = 'test123'
                            elif name.lower() in ['username', 'user', 'email']:
                                fields[name] = 'admin'
                            else:
                                fields[name] = 'test'
                    
                    endpoints.append({
                        'url': full_url,
                        'method': method,
                        'fields': fields,
                        'source': 'form_action'
                    })
                    self.result += f"[+] Found form: {method} {full_url}"
            
            return endpoints
            
        except Exception as e:
            self.result += f"[-] Error analyzing HTML: {e}"
            return []
    
    def discover_from_javascript(self, url):
        """Discover endpoints from JavaScript files"""
        self.result += f"[+] Analyzing JavaScript files from: {url}"
        endpoints = []
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all script tags
            script_urls = []
            
            # External scripts
            for script in soup.find_all('script', src=True):
                script_url = urljoin(url, script['src'])
                script_urls.append(script_url)
            
            # Inline scripts
            inline_scripts = []
            for script in soup.find_all('script', src=False):
                if script.string:
                    inline_scripts.append(script.string)
            
            # Analyze external scripts
            for script_url in script_urls:
                try:
                    js_response = self.session.get(script_url, timeout=5)
                    js_content = js_response.text
                    found_endpoints = self.extract_api_endpoints(js_content, url)
                    endpoints.extend(found_endpoints)
                except:
                    continue
            
            # Analyze inline scripts
            for js_content in inline_scripts:
                found_endpoints = self.extract_api_endpoints(js_content, url)
                endpoints.extend(found_endpoints)
            
            return endpoints
            
        except Exception as e:
            self.result += f"[-] Error analyzing JavaScript: {e}"
            return []
    
    def extract_api_endpoints(self, js_content, base_url):
        """Extract API endpoints from JavaScript content"""
        endpoints = []
        
        # Comprehensive regex patterns for API discovery
        patterns = [
            # Direct URL patterns
            (r'["\']https?://[^"\']*(?:api|login|auth|backend)[^"\']*["\']', 'direct_url'),
            (r'["\'][^"\']*(?:/api/|/login|/auth|/backend)[^"\']*["\']', 'relative_api'),
            
            # Function call patterns
            (r'fetch\s*\(\s*["\']([^"\']+)["\']', 'fetch'),
            (r'axios\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']', 'axios'),
            (r'\.ajax\s*\(\s*[^}]*url\s*:\s*["\']([^"\']+)["\']', 'jquery'),
            (r'XMLHttpRequest.*?open\s*\(\s*["\']POST["\'],\s*["\']([^"\']+)["\']', 'xhr'),
            
            # React/Modern patterns
            (r'action\s*:\s*["\']([^"\']+)["\']', 'action'),
            (r'endpoint\s*:\s*["\']([^"\']+)["\']', 'endpoint'),
            (r'baseURL\s*:\s*["\']([^"\']+)["\']', 'baseurl'),
        ]
        
        for pattern, pattern_type in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                # Clean the match
                endpoint = match.strip('\'"')
                
                # Skip if not relevant
                if not endpoint or endpoint.startswith('data:') or endpoint.startswith('#'):
                    continue
                
                # Convert relative URLs to absolute
                if endpoint.startswith('/'):
                    full_url = urljoin(base_url, endpoint)
                elif not endpoint.startswith('http'):
                    continue  # Skip if can't resolve
                else:
                    full_url = endpoint
                
                # Filter for relevant endpoints
                if any(keyword in full_url.lower() for keyword in ['login', 'auth', 'api', 'backend', 'signin']):
                    endpoints.append({
                        'url': full_url,
                        'method': 'POST',
                        'fields': {'username': 'admin', 'password': 'test123'},
                        'source': f'js_{pattern_type}'
                    })
                    self.result += f"[+] Found JS endpoint: {full_url} (via {pattern_type})"
        
        return endpoints
    
    def probe_common_endpoints(self, base_url):
        """Probe common API endpoint patterns"""
        self.result += f"[+] Probing common endpoints on: {base_url}"
        endpoints = []
        
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common endpoint patterns
        common_paths = [
            '/api/login', '/api/auth', '/api/signin',
            '/login', '/auth', '/signin',
            '/backend/login', '/backend/auth',
            '/v1/login', '/v1/auth',
            '/admin/login', '/admin/auth'
        ]
        
        for path in common_paths:
            test_url = base + path
            
            try:
                # Quick HEAD request to check if endpoint exists
                response = self.session.head(test_url, timeout=3)
                
                # If not 404, it might be valid
                if response.status_code != 404:
                    endpoints.append({
                        'url': test_url,
                        'method': 'POST',
                        'fields': {'username': 'admin', 'password': 'test123'},
                        'source': 'common_probe',
                        'status_code': response.status_code
                    })
                    self.result += f"[+] Found endpoint: {test_url} (status: {response.status_code})"
                    
            except:
                continue
        
        return endpoints
    
    def test_endpoint_with_sqlmap(self, endpoint, minimal=True):
        """Test endpoint with sqlmap"""
        url = endpoint['url']
        method = endpoint.get('method', 'POST')
        fields = endpoint.get('fields', {})
        base_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_dir, "sqlmap-dev/sqlmap.py")
        # Build form data
        form_data = '&'.join([f"{k}={v}" for k, v in fields.items()])
        
        cmd = ['python', file_path, '-u', url, '--batch']
        
        if method == 'POST' and form_data:
            cmd.extend(['--data', form_data])
        
        if minimal:
            cmd.extend([
                '--technique', 'B',
                '-v 0',
                '--ignore-redirects',
                '--timeout', '30',
                '--retries', '1'
            ])
        
        self.result += f"[+] Testing: {url}"
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'injectable' in result.stdout.lower() or 'parameter' in result.stdout.lower():
                self.result += f"[!] VULNERABLE: {url}"
                return True
            else:
                self.result += f"[-] Not vulnerable: {url}"
                return False
                
        except Exception as e:
            self.result += f"[-] Error testing {url}: {e}"
            return False
    
    def full_discovery(self, target_url, test_vulnerabilities=True):
        """Complete discovery pipeline"""
        self.result += f"[+] Starting static analysis for: {target_url}"
        
        all_endpoints = []
        
        # Method 1: HTML analysis
        html_endpoints = self.discover_from_html(target_url)
        all_endpoints.extend(html_endpoints)
        
        # Method 2: JavaScript analysis
        js_endpoints = self.discover_from_javascript(target_url)
        all_endpoints.extend(js_endpoints)
        
        # Method 3: Common endpoint probing
        common_endpoints = self.probe_common_endpoints(target_url)
        all_endpoints.extend(common_endpoints)
        
        # Remove duplicates
        unique_endpoints = []
        seen_urls = set()
        for endpoint in all_endpoints:
            if endpoint['url'] not in seen_urls:
                unique_endpoints.append(endpoint)
                seen_urls.add(endpoint['url'])
        
        self.result += f"\n[+] Discovered {len(unique_endpoints)} unique endpoints"
        
        # Test for SQL injection if requested
        if test_vulnerabilities and unique_endpoints:
            self.result += "\n[+] Testing for SQL injection vulnerabilities..."
            vulnerable_endpoints = []
            
            for endpoint in unique_endpoints:
                if self.test_endpoint_with_sqlmap(endpoint):
                    vulnerable_endpoints.append(endpoint)
            
            self.result += f"\n[+] Results: {len(vulnerable_endpoints)} vulnerable endpoints found"
            return unique_endpoints, vulnerable_endpoints
        
        return unique_endpoints, []

@tool(name="sql_injection", description="Runs Nikto to determine any initial security vulnerabilities with the given website.", permission=ToolPermission.ADMIN)
def sql_injection_test(target_url: str) -> str:   
    discovery = StaticBackendDiscovery()
    endpoints, vulnerable = discovery.full_discovery(target_url, test_vulnerabilities=True)
    
    discovery.result += "\n" + "="*60
    discovery.result += "DISCOVERY RESULTS"
    discovery.result += "="*60
    
    if endpoints:
        discovery.result += f"\nAll Discovered Endpoints ({len(endpoints)}):"
        for i, endpoint in enumerate(endpoints, 1):
            discovery.result += f"{i}. {endpoint['method']} {endpoint['url']}"
            discovery.result += f"   Source: {endpoint['source']}"
            if endpoint.get('fields'):
                discovery.result += f"   Fields: {endpoint['fields']}"
            discovery.result += "\n"
    
    if vulnerable:
        discovery.result += f"\nVULNERABLE ENDPOINTS ({len(vulnerable)}):"
        for endpoint in vulnerable:
            discovery.result += f"[!] {endpoint['url']}"
    else:
        discovery.result += "\n[-] No SQL injection vulnerabilities found)"
    return discovery.result

print(sql_injection_test("https://www.transformatech.com"))