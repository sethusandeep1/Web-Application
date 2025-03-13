import time
import pandas as pd
import subprocess
from zapv2 import ZAPv2
import requests

# Configuration
zap_api_key = 'zap_api_key'  # Replace with ZAP API key
zap_base_url = 'http://localhost:8080'
csv_file_path = 'urls.csv'
burp_api_url = 'http://localhost:1337'
burp_api_key = 'burp_api_key'  # Replace with BurpSuite API key
captcha_api_key = '2captcha_api_key'  # Replace with 2Captcha API key

# Initialize ZAP instance
zap = ZAPv2(apikey=zap_api_key, proxies={'http': zap_base_url, 'https': zap_base_url})

def solve_captcha(site_key, url):
    """Solve CAPTCHA using 2Captcha service."""
    captcha_request_url = 'http://2captcha.com/in.php'
    captcha_request_payload = {
        'key': captcha_api_key,
        'method': 'userrecaptcha',
        'googlekey': site_key,
        'pageurl': url,
        'json': 1
    }
    response = requests.post(captcha_request_url, data=captcha_request_payload)
    request_id = response.json().get('request')

    captcha_result_url = f'http://2captcha.com/res.php?key={captcha_api_key}&action=get&id={request_id}&json=1'
    while True:
        result = requests.get(captcha_result_url).json()
        if result.get('status') == 1:
            return result.get('request')
        time.sleep(5)  # Wait for a few seconds before checking again

def bypass_captcha(session, target_url):
    """Bypass CAPTCHA by solving and submitting the CAPTCHA token."""
    site_key = 'example_site_key'  # Replace with the actual site key of the CAPTCHA
    captcha_token = solve_captcha(site_key, target_url)
    
    captcha_submission_payload = {
        'g-recaptcha-response': captcha_token,
        'other_form_fields': 'values'  # Include other form fields required by the site
    }
    session.post(target_url, data=captcha_submission_payload)

def enumerate_subdomains(domain):
    """Enumerate subdomains using Sublist3r."""
    subprocess.run(['sublist3r', '-d', domain, '-o', 'subdomains.txt'])
    with open('subdomains.txt', 'r') as f:
        subdomains = f.read().splitlines()
    return subdomains

def collect_urls_from_spider(spider_results):
    """Collect URLs from spider results."""
    urls = []
    for result in spider_results:
        urls.append(result['href'])
    return urls

def burp_scan(target_url):
    """Start a BurpSuite scan on the given URL."""
    headers = {'Authorization': burp_api_key}
    scan_data = {'url': target_url, 'crawl': 'true', 'audit': 'true'}
    response = requests.post(f'{burp_api_url}/v0.1/scan', json=scan_data, headers=headers)
    if response.status_code == 200:
        print(f'BurpSuite scan started for {target_url}')
    else:
        print(f'Error starting BurpSuite scan: {response.text}')

def perform_vapt(base_url):
    """Perform VAPT on the given base URL."""
    session = requests.Session()

    # CAPTCHA Bypass (if necessary)
    print(f'Attempting CAPTCHA bypass for {base_url}')
    bypass_captcha(session, base_url)

    # Subdomain Enumeration
    domain = base_url.split('//')[-1].split('/')[0]
    print(f'Starting subdomain enumeration for {domain}')
    subdomains = enumerate_subdomains(domain)
    print(f'Found subdomains: {subdomains}')

    # WhatWeb: Identify web technologies with additional plugins
    print(f'Starting WhatWeb scan on {base_url}')
    subprocess.run(['whatweb', '--plugin', 'wordpress', '--plugin', 'drupal', '--plugin', 'joomla', base_url])

    # Nikto: Scan for vulnerabilities
    print(f'Starting Nikto scan on {base_url}')
    subprocess.run(['nikto', '-h', base_url])

    # Nuclei: Scan for vulnerabilities using templates
    print(f'Starting Nuclei scan on {base_url}')
    subprocess.run(['nuclei', '-u', base_url])

    # Wapiti: Web application vulnerability scanner
    print(f'Starting Wapiti scan on {base_url}')
    subprocess.run(['wapiti', '-u', base_url])

    # WPScan: WordPress vulnerability scanner
    print(f'Starting WPScan on {base_url}')
    subprocess.run(['wpscan', '--url', base_url])

    # OWASP ZAP: Spidering (Crawling)
    print(f'Starting traditional spider on {base_url}')
    zap.spider.scan(base_url)
    while int(zap.spider.status()) < 100:
        print(f'Spider progress: {zap.spider.status()}%')
        time.sleep(2)
    print('Traditional spider completed')

    spider_results = zap.spider.results()
    urls = collect_urls_from_spider(spider_results)

    print(f'Starting AJAX spider on {base_url}')
    zap.ajaxSpider.scan(base_url)
    while zap.ajaxSpider.status == 'running':
        print(f'AJAX Spider status: {zap.ajaxSpider.status}')
        time.sleep(2)
    print('AJAX spider completed')

    ajax_spider_results = zap.ajaxSpider.results()
    urls += collect_urls_from_spider(ajax_spider_results)

    # Removing duplicates
    urls = list(set(urls))

    # Passive Scanning
    print('Starting passive scan...')
    while int(zap.pscan.records_to_scan) > 0:
        print(f'Records to passive scan: {zap.pscan.records_to_scan}')
        time.sleep(2)
    print('Passive scan completed')

    # Active Scanning
    for url in urls:
        print(f'Starting active scan on {url}')
        zap.ascan.scan(url)
        while int(zap.ascan.status()) < 100:
            print(f'Active scan progress: {zap.ascan.status()}%')
            time.sleep(5)
        print(f'Active scan completed for {url}')

    # Collecting Alerts
    all_alerts = []
    for url in urls:
        alerts = zap.core.alerts(baseurl=url)
        all_alerts.extend(alerts)
        for alert in alerts:
            print(f"Alert: {alert['alert']}, Risk: {alert['risk']}, URL: {alert['url']}, Parameter: {alert['param']}, Description: {alert['description']}")

    # Generate and save report
    report_filename = f'zap_report_{base_url.replace("http://", "").replace("https://", "").replace("/", "_")}.html'
    html_report = zap.core.htmlreport()
    with open(report_filename, 'w') as report_file:
        report_file.write(html_report)

    print(f'Report has been saved as {report_filename}')

    # BurpSuite: Active scan using BurpSuite API
    for url in urls:
        print(f'Starting BurpSuite scan on {url}')
        burp_scan(url)


# Read URLs from the CSV file
urls_df = pd.read_csv(csv_file_path)

# Perform VAPT for each base URL
for index, row in urls_df.iterrows():
    base_url = row['url']
    print(f'\n\nStarting VAPT for {base_url}')
    perform_vapt(base_url)
    print(f'VAPT for {base_url} completed\n\n')

print('All URLs have been scanned.')
