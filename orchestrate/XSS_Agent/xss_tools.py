import subprocess
import os
from zapv2 import ZAPv2

dir_path = os.path.dirname(__file__)

os.chdir(dir_path + '/../ZAP/Zed Attack Proxy')
cmd = [
    "zap.bat",
    "-daemon",
    "-port", "8090",
    "-host", "127.0.0.1",
    "-config", "api.key=12345"
]

process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    shell=True,
    text=True
)

os.chdir(dir_path)

api_key = '12345'
target = 'http://www.transformatech.com'
zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8090'})

# Access and spider the target
zap.urlopen(target)
zap.spider.scan(target)
# while int(zap.spider.status()) < 100:
    # print(f'Spider progress: {zap.spider.status()}%')
    

# Enable only XSS scanners
zap.ascan.disable_all_scanners()
zap.ascan.enable_scanners('40012,40014,40016,40017')

# Start active scan
scan_id = zap.ascan.scan(target)
# while int(zap.ascan.status(scan_id)) < 100:
    # print(f'Scan progress: {zap.ascan.status(scan_id)}%')

# Print XSS alerts
alerts = zap.core.alerts(baseurl=target)
print("[*] XSS Alerts:")
bNoAlerts = True
for alert in alerts:
    if 'xss' in alert['alert'].lower():
        print(f"- {alert['alert']} at {alert['url']}")
        bNoAlerts = False
if bNoAlerts:
    print("No XSS Vulnerabilities detected")