#!/usr/bin/env python3
import subprocess
import datetime
from zapv2 import ZAPv2
import time
from tqdm import tqdm
import requests
from bs4 import BeautifulSoup
import re 
import json
import socket 
from pymongo import MongoClient
from urllib.parse import urlparse, urlunparse
import xmltodict 

# Configuration ; To Be Hardcoded
zap_api_key = 'f0hgm5gugb6rb8ja4tn5t7e0kk'
zap_base_url = 'https://localhost:8080'
burp_api_url = 'https://localhost:1337'
burp_api_key = 'burp_api_key'
captcha_api_key = '3b0c2252af451bc07189951f5c617993'
wpscan_api_token= 'w0e6676N2TUUxzOCEZbD8NbsXkLkCtOSTeXcGzaaDg4'
defectdojo_api_key = '548afd6fab3bea9794a41b31da0e9404f733e222'
defectdojo_base_url = 'https://defectdojo-instance.com/api/v2'

# MongoDB Configuration
mongo_client = MongoClient('localhost', 27017)
db = mongo_client['vapt_db']
urls_collection = db['urls']
scans_collection = db['scans']
scan_results_collection = db['scan_results']
subdomains_collection = db['subdomains']

# Initialize ZAP instance
zap = ZAPv2(apikey=zap_api_key, proxies={'https': zap_base_url, 'httpss': zap_base_url})
scan_results = {}

def drop_collections():
    """Drop existing MongoDB collections."""
    try:
        db.drop_collection('urls')
        db.drop_collection('scans')
        db.drop_collection('scan_results')
        db.drop_collection('subdomains')
        print('Existing collections dropped successfully.')
    except Exception as e:
        print(f'Error dropping collections: {e}')

def store_subdomains_in_database(target_url, subdomains):
    """Store subdomains in the database."""
    try:
        data = [{'url': target_url, 'subdomain': subdomain} for subdomain in subdomains]
        subdomains_collection.insert_many(data)
        print(f'Subdomains stored in database for {target_url}')
    except Exception as e:
        print(f'Error storing subdomains in database for {target_url}: {e}')

def wait_for_passive_scan():
    while int(zap.pscan.records_to_scan) > 0:
        print(f'Passive Scan progress: {zap.pscan.records_to_scan} records left')
        time.sleep(2)
    print('Passive scan completed')

def enumerate_subdomains(target_url):
    """Enumerate subdomains using Amass and store in MongoDB."""
    try:
        # Strip scheme from URL
        domain = re.sub(r'^https?://', '', target_url).strip('/')
        print(f'Starting Amass enumeration for {domain}')
        
        # Define Amass command with various flags for maximum utilization
        amass_cmd = [ 'sudo' ,
            'amass', 'enum',
            '-active',              # Enable active recon methods
            '-alts',                # Enable generation of altered names
            '-brute',               # Perform brute force subdomain enumeration
            '-min-for-recursive', '3',  # Minimum subdomain labels seen before recursive brute forcing
            '-p', '80,443,8080',    # Ports to scan
            '-ip',                  # Show IP addresses for discovered names
            '-ipv4',                # Show IPv4 addresses
            '-ipv6',                # Show IPv6 addresses
            '-timeout', '30',       # Set timeout to 30 minutes
            '-d', domain            # Target domain
        ]

        # Run Amass enumeration
        result = subprocess.run(amass_cmd, capture_output=True, text=True, check=True)
        subdomains = result.stdout.splitlines()
        
        print(f'Amass enumeration completed for {domain}. Subdomains found: {subdomains}')
        time.sleep(2)
        
        # Store subdomains in MongoDB
        if subdomains:
            store_subdomains_in_database(target_url, subdomains)
        
        return subdomains
    except subprocess.CalledProcessError as e:
        print(f'Error during Amass enumeration for {target_url}: {e}')
        return []
    except FileNotFoundError as fnfe:
        print(f'Command not found: {fnfe}')
        return []

def nmap_scan(target_url, cms=None):
    """Perform an Nmap scan on the given URL and return results in JSON format."""
    try:
        # Parse the URL to extract the hostname
        parsed_url = urlparse(target_url)
        hostname = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        # Ensure the hostname does not include the scheme
        if hostname.startswith('https://') or hostname.startswith('http://'):
            hostname = hostname.split('//')[1]

        # Resolve the hostname to an IP address
        target_ip = socket.gethostbyname(hostname)
        
        if not hostname:
            print(f'Invalid URL provided: {target_url}')
            return None
        
        # OWASP Top 10 related scripts
        owasp_scripts = [
            'http-sql-injection',          # A1: Injection
            'http-xssed',                  # A3: Cross-Site Scripting (XSS)
            'http-open-redirect',          # A10: Insufficient Logging & Monitoring
            'http-userdir-enum',           # A5: Broken Access Control
            'http-config-backup',          # A6: Security Misconfiguration
            'http-default-accounts',       # A2: Broken Authentication
            'http-brute',                  # A2: Broken Authentication
            'http-enum',                   # A4: Insecure Design
            'http-methods',                # A5: Broken Access Control
            'http-headers',                # A6: Security Misconfiguration
            'ssl-cert',                    # A6: Security Misconfiguration
            'ssl-enum-ciphers',            # A6: Security Misconfiguration
            'tls-ticketbleed',             # A6: Security Misconfiguration
            'http-csrf'                    # A8: Cross-Site Request Forgery (CSRF)
        ]

        # Nmap Vulnerability scripts
        vuln_scripts = [
            'distcc-cve2004-2687',        # Distcc CVE-2004-2687
            'ftp-vuln-cve2010-4221',      # FTP CVE-2010-4221
            'http-vuln-cve2011-3192',     # HTTP CVE-2011-3192
            'http-vuln-cve2011-3368',     # HTTP CVE-2011-3368
            'http-vuln-cve2012-1823',     # HTTP CVE-2012-1823
            'http-vuln-cve2013-0156',     # HTTP CVE-2013-0156
            'http-vuln-cve2013-7091',     # HTTP CVE-2013-7091
            'http-vuln-cve2014-3704',     # HTTP CVE-2014-3704
            'http-vuln-cve2015-1427',     # HTTP CVE-2015-1427
            'http-vuln-cve2015-1635',     # HTTP CVE-2015-1635
            'http-vuln-cve2017-5638',     # HTTP CVE-2017-5638
            'http-vuln-cve2017-5689',     # HTTP CVE-2017-5689
            'http-vuln-cve2017-8917',     # HTTP CVE-2017-8917
            'mysql-vuln-cve2012-2122',    # MySQL CVE-2012-2122
            'samba-vuln-cve-2012-1182',   # Samba CVE-2012-1182
            'smb-vuln-cve-2017-7494',     # SMB CVE-2017-7494
            'smb-vuln-cve2009-3103',      # SMB CVE-2009-3103
            'vulners'                     # Vulners integration
        ]

        # CMS-specific vulnerability scripts
        cms_scripts = []

        if cms == 'WordPress':
            cms_scripts = [
                'http-wordpress-users',             # WordPress users enumeration
                'http-wordpress-brute',             # WordPress brute force
                'http-wordpress-timthumb',          # WordPress TimThumb vulnerability
                'http-wordpress-theme'              # WordPress themes enumeration
            ]
        elif cms == 'Drupal':
            cms_scripts = [
                'http-vuln-cve2014-3704',
                'http-vuln-drupalgeddon2'
            ]
        elif cms == 'Joomla':
            cms_scripts = [
                'http-vuln-cve2015-85620',
                'http-vuln-cve2017-8917'
            ]

        # Other CMS-independent scripts
        other_scripts = [
            'http-backup-finder',              # Backup file finder
            'http-config-backup',              # Config file backup finder
            'http-cors',                       # CORS configuration
            'http-cookie-flags',               # Cookie security flags
            'http-internal-ip-disclosure',     # Internal IP address disclosure
            'http-slowloris',                  # Slowloris DoS attack check
            'http-open-redirect'               # Open redirect vulnerabilities
        ]

        # Combine scripts into a single list
        all_scripts = owasp_scripts + vuln_scripts + cms_scripts + other_scripts

        results = []

        # Execute Nmap scan for each script
        for script in all_scripts:
            nmap_command = [
                'nmap', '-p-', '--script', script, '-oX', '-', target_ip
            ]
            try:
                result = subprocess.run(nmap_command, capture_output=True, text=True, check=True)
                xml_output = result.stdout
                dict_output = xmltodict.parse(xml_output)

                # Add metadata
                dict_output['script'] = script
                dict_output['target_url'] = target_url
                dict_output['target_ip'] = target_ip

                results.append(dict_output)
                print(f"Results for {script}:\n{json.dumps(dict_output, indent=4)}")

            except subprocess.CalledProcessError as e:
                print(f"Error running nmap for script {script}: {e}")

    except Exception as e:
        print(f"Error resolving hostname or running Nmap: {e}")

    return results

def start_active_scan(target_url):
    if not urlparse(target_url).scheme:
            target_url = f'https://{target_url}'
    print(f'Starting Active Scan on {target_url}')
    zap.ascan.scan(target_url)
    with tqdm(total=100, desc='Active Scan progress') as pbar:
        while int(zap.ascan.status()) < 100:
            current_progress = int(zap.ascan.status())
            pbar.update(current_progress - pbar.n)
            time.sleep(1)  # Delay for 1 second between updates
        pbar.update(100 - pbar.n)  # Ensure progress bar reaches 100%
    print('Active Scan completed')

def start_passive_scan(target_url):
    if not urlparse(target_url).scheme:
            target_url = f'https://{target_url}'
    print(f'Starting Passive Scan on {target_url}')
    zap.urlopen(target_url)
    wait_for_passive_scan()

def start_spider(target_url):
    if not urlparse(target_url).scheme:
            target_url = f'https://{target_url}'
    print(f'Starting Spider on {target_url}')
    zap.spider.scan(target_url)
    with tqdm(total=100, desc='Spider Scan progress') as pbar:
        while zap.spider.status() < 100:
            current_progress = zap.spider.status()
            pbar.update(current_progress - pbar.n)
            time.sleep(1)  
        pbar.update(100 - pbar.n)  
    print('Spider scan completed')

def generate_zap_reports(target_url):
    zap_report_json = zap.core.jsonreport()    
    zap_alerts = zap.core.alerts(baseurl=target_url)
    return json.loads(zap_report_json), zap_alerts
   
#def burp_scan(target_url):
 #   """Start a BurpSuite scan on the given URL."""
  #  headers = {'Authorization': burp_api_key}
   # scan_data = {'url': target_url, 'crawl': 'true', 'audit': 'true'}
    #response = requests.post(f'{burp_api_url}/v0.1/scan', json=scan_data, headers=headers)
 #   if response.status_code == 200:
  #      print(f'BurpSuite scan started for {target_url}')
        # Store the BurpSuite report path
   #     report_path = f'{output_dir}/burpsuite_{target_url}.html'
    #    with open(report_path, 'w') as f:
     #       f.write(response.text)
      #  return report_path
   # else:
    #    print(f'Error starting BurpSuite scan: {response.text}')
     #   return None

def metasploit_scan(target_url):
    """Perform a comprehensive Metasploit scan on the given URL"""
    parsed_url = urlparse(target_url)
    
    if not parsed_url.scheme:
        target_url = f'https://{target_url}'
    elif parsed_url.scheme not in ['https', 'httpss']:
        raise ValueError("Unsupported URL scheme. Only https and httpsS are supported.")
    
    scan_results = {}
    target_host = parsed_url.netloc

    try:
        #Metasploit commands for various auxiliary modules
        commands_list = [
            # https Version scanner
            [
                'use auxiliary/scanner/https/https_version',
                f'set RHOSTS {target_host}',
                'run',
                'exit'
            ],
            # https Options scanner
            [
                'use auxiliary/scanner/https/options',
                f'set RHOSTS {target_host}',
                'run',
                'exit'
            ],
            # https PUT scanner
            [
                'use auxiliary/scanner/https/https_put',
                f'set RHOSTS {target_host}',
                'run',
                'exit'
            ],
            # Heartbleed scanner
            [
                'use auxiliary/scanner/ssl/openssl_heartbleed',
                f'set RHOSTS {target_host}',
                'run',
                'exit'
            ],
            # Directory listing scanner
            [
                'use auxiliary/scanner/https/dir_listing',
                f'set RHOSTS {target_host}',
                'run',
                'exit'
            ]
        ]

        def run_msf_command(commands):
            msf_command = ['sudo', 'msfconsole', '-q', '-x', '; '.join(commands)]
            result = subprocess.run(
                msf_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.stderr:
                print(f'Error during Metasploit scan: {result.stderr}')
            return result.stdout

        for commands in commands_list:
            module_name = commands[0].split()[-1]
            scan_output = run_msf_command(commands)
            scan_results[module_name] = scan_output

    except Exception as e:
        print(f'Error during Metasploit scan for {target_url}: {e}')
        return None

    return scan_results

def cmsmap(target_url, cms):
    """Perform a CMSMap scan on the given URL for the specified CMS."""
    try:
        result = subprocess.run(['python3', 'cmsmap.py', '-t', target_url, '-f', cms], capture_output=True, text=True, check=True)
        print(f'CMSMap scan completed for {target_url} ({cms})')
        return {"cmsmap_result": result.stdout}
    except subprocess.CalledProcessError as e:
        print(f'Error performing CMSMap scan for {cms}: {e}')
        return {"cmsmap_error": str(e)}

def arachni_scan(target_url):
    """Perform an Arachni scan on the given URL."""
    try:
        result = subprocess.run(['arachni', target_url, '--output-only-positives'], capture_output=True, text=True, check=True)
        print(f'Arachni scan completed for {target_url}')
        return {"arachni_result": result.stdout}
    except subprocess.CalledProcessError as e:
        print(f'Error performing Arachni scan: {e}')
        return {"arachni_error": str(e)}

def owasp_dependency_check(target_url):
    """Perform an OWASP Dependency Check scan on the given URL."""
    try:
        result = subprocess.run(['dependency-check', '--scan', target_url, '--format', 'JSON'], capture_output=True, text=True, check=True)
        print(f'OWASP Dependency Check completed for {target_url}')
        return {"owasp_dependency_check_result": result.stdout}
    except subprocess.CalledProcessError as e:
        print(f'Error performing OWASP Dependency Check: {e}')
        return {"owasp_dependency_check_error": str(e)}

def wpscan(target_url):
    """Perform a WPScan on the given URL using WPScan API token."""
    try:
        if not urlparse(target_url).scheme:
            target_url = f'https://{target_url}'
        wpscan_result = subprocess.run(['wpscan', '--url', target_url, '--api-token', wpscan_api_token],
                                       capture_output=True, text=True, check=True)
        print(f'WPScan completed for {target_url}')
        cmsmap_result = cmsmap(target_url, 'wp')
        arachni_result = arachni_scan(target_url)
        return json.dumps({"wpscan_result": wpscan_result.stdout, **cmsmap_result, **arachni_result}, indent=4)
    except subprocess.CalledProcessError as e:
        print(f'Error performing WPScan: {e}')
        return None

def droopescan(target_url):
    """Perform a Droopescan on the given URL."""
    try:
        if not urlparse(target_url).scheme:
            target_url = f'https://{target_url}'
        droopescan_result = subprocess.run(['droopescan', 'scan', 'drupal', '-u', target_url], capture_output=True, text=True, check=True)
        print(f'Droopescan completed for {target_url}')
        cmsmap_result = cmsmap(target_url, 'drupal')
        arachni_result = arachni_scan(target_url)
        return json.dumps({"droopescan_result": droopescan_result.stdout, **cmsmap_result, **arachni_result}, indent=4)
    except subprocess.CalledProcessError as e:
        print(f'Error performing Droopescan: {e}')
        return None

def joomscan(target_url):
    """Perform a Joomscan on the given URL."""
    try:
        if not urlparse(target_url).scheme:
            target_url = f'https://{target_url}'
        joomscan_result = subprocess.run(['joomscan', '-u', target_url], capture_output=True, text=True, check=True)
        print(f'Joomscan completed for {target_url}')
        
        # Perform OWASP Joomla Security scan
        owasp_joomla_result = subprocess.run(['python3', 'joomscan.py', target_url], capture_output=True, text=True, check=True)
        print(f'OWASP Joomla Security scan completed for {target_url}')
        cmsmap_result = cmsmap(target_url, 'joomla')
        arachni_result = arachni_scan(target_url)
        return json.dumps({"joomscan_result": joomscan_result.stdout, "owasp_joomla_scan_result": owasp_joomla_result.stdout, **cmsmap_result, **arachni_result}, indent=4)
    except subprocess.CalledProcessError as e:
        print(f'Error performing Joomscan: {e}')
        return None

def identify_cms(target_url):
    """Identify CMS used by the website with a verification mechanism."""
    try:
        # Parse the URL and ensure it has a scheme (http or https)
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme:
            target_url = f'https://{parsed_url.path}'
            parsed_url = urlparse(target_url)

        # Validate URL components
        if not parsed_url.netloc:
            raise ValueError(f"Invalid URL: {target_url}")

        # Normalize URL (remove any invalid characters)
        target_url = urlunparse(parsed_url._replace(path=''))

        # Initialize detected CMS and output as 'Unknown'
        detected_cms = 'Unknown'
        output = ''

        # Attempt to run the whatweb tool with the given URL
        try:
            result = subprocess.run(
                ['whatweb', '--aggression=3', target_url],
                capture_output=True,
                text=True,
                check=True
            )

            # Convert the output to lowercase for consistent checks
            output = result.stdout.lower()
        except subprocess.CalledProcessError as e:
            print(f'Error identifying CMS with WhatWeb: {e}')

        # Check for known CMS identifiers in the whatweb output
        if 'WordPress' in output:
            detected_cms = 'WordPress'
        elif 'Drupal' in output:
            detected_cms = 'Drupal'
        elif 'Joomla' in output:
            detected_cms = 'Joomla'

        # Double-check using HTML inspection
        cms_verification = 'Unknown'
        try:
            response = requests.get(target_url, timeout=10)
            response.raise_for_status()  # Raise an error if the request fails

            # Use BeautifulSoup to parse the HTML content
            soup = BeautifulSoup(response.content, 'html.parser')

            # Check for WordPress specific indicators
            if soup.find('meta', {'name': 'generator', 'content': 'WordPress'}):
                cms_verification = 'WordPress'
            elif any('wp-content' in script.get('src', '') for script in soup.find_all('script', src=True)):
                cms_verification = 'WordPress'

            # Check for Drupal specific indicators
            if soup.find('meta', {'name': 'generator', 'content': 'Drupal'}):
                cms_verification = 'Drupal'
            elif any('sites/all' in link.get('href', '') for link in soup.find_all('link', href=True)):
                cms_verification = 'Drupal'

            # Check for Joomla specific indicators
            if soup.find('meta', {'name': 'generator', 'content': 'Joomla'}):
                cms_verification = 'Joomla'
            elif any('templates/' in link.get('href', '') for link in soup.find_all('link', href=True)):
                cms_verification = 'Joomla'

        except requests.RequestException as e:
            print(f'Error fetching page for verification: {e}')
        except Exception as e:
            print(f'Unexpected error during CMS verification: {e}')

        # Compare results from whatweb and verification method
        if cms_verification != 'Unknown' and cms_verification == detected_cms:
            return detected_cms
        elif cms_verification != 'Unknown':
            print(f'Discrepancy found: WhatWeb detected {detected_cms}, verification detected {cms_verification}')
            return cms_verification
        else:
            return detected_cms

    except ValueError as e:
        print(e)
        return 'Unknown'
    except Exception as e:  # Catch any other potential exceptions
        print(f'Unexpected error: {e}')
        return 'Unknown'
    
def get_defectdojo_engagement(product_id, engagement_name):
    url = f"{defectdojo_base_url}/engagements/"
    headers = {"Authorization": f"Token {defectdojo_api_key}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    engagements = response.json().get("results", [])
    for engagement in engagements:
        if engagement["product"] == product_id and engagement["name"] == engagement_name:
            return engagement["id"]
    return None

def create_defectdojo_engagement(product_id, engagement_name):
    """Creates a new engagement in DefectDojo."""
    url = f"{defectdojo_base_url}/engagements/"
    headers = {"Authorization": f"Token {defectdojo_api_key}", "Content-Type": "application/json"}
    engagement_data = {
        "product": product_id,
        "name": engagement_name,
        "target_start": str(datetime.datetime.now().date()),
        "target_end": str(datetime.datetime.now().date()),
        "lead": 1,  # Adjust lead ID as needed
        "status": "In Progress",
        "engagement_type": "CI/CD",  # Adjust as needed
    }
    response = requests.post(url, headers=headers, data=json.dumps(engagement_data))
    response.raise_for_status()
    return response.json()["id"]


def create_defectdojo_test(engagement_id, target_url):
    url = f"{defectdojo_base_url}/tests/"
    headers = {"Authorization": f"Token {defectdojo_api_key}", "Content-Type": "application/json"}
    test_data = {
        "engagement": engagement_id,
        "title": f"VAPT Test for {target_url}",
        "test_type": 1,  # Generic Test Type ID
        "target_start": str(datetime.datetime.now()),
        "target_end": str(datetime.datetime.now()),
    }
    response = requests.post(url, headers=headers, data=json.dumps(test_data))
    response.raise_for_status()
    return response.json()["id"]

def upload_defectdojo_finding(test_id, target_url, description):
    url = f"{defectdojo_base_url}/findings/"
    headers = {"Authorization": f"Token {defectdojo_api_key}", "Content-Type": "application/json"}
    finding_data = {
        "test": test_id,
        "title": f"Vulnerability found in {target_url}",
        "description": description,
        "severity": "Medium",  # Modify severity based on needs
        "mitigation": "Review and mitigate the vulnerability",
        "impact": "Potential security risk",
        "references": "https://example.com/reference",
        "url": target_url,
        "date": str(datetime.datetime.now().date())
    }
    response = requests.post(url, headers=headers, data=json.dumps(finding_data))
    response.raise_for_status()
    return response.json()

def perform_vapt(target_url):
    try:
        # Insert URL into the database and get the ID
        try:
            url_doc = {'url': target_url, 'scan_status': 'In Progress'}
            url_id = urls_collection.insert_one(url_doc).inserted_id
        except Exception as e:
            print(f'Error inserting URL into database: {e}')
            return  # Return early if there's an error inserting into the database
        
        # Identify CMS and perform scans
        try:
            print(f'Identifying CMS for {target_url}')
            scans_collection.insert_one({'url_id': url_id, 'scan_type': 'CMS Identification', 'status': 'In Progress'})
            cms = identify_cms(target_url)
            scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'CMS Identification', 'result': cms})
            time.sleep(180)
            scans_collection.update_one({'url_id': url_id, 'scan_type': 'CMS Identification'}, {'$set': {'status': 'Completed'}})
        #Arachni Scans    
            print(f'Starting Arachni scan for {target_url}')
            scans_collection.insert_one({'url_id': url_id, 'scan_type': 'Arachni', 'status': 'In Progress'})
            arachni_result = arachni_scan(target_url)
            scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'Arachni', 'result': arachni_result})
            time.sleep(60)
            scans_collection.update_one({'url_id': url_id, 'scan_type': 'Arachni'}, {'$set': {'status': 'Completed'}})

        # OWASP Dependency Check
            print(f'Starting OWASP Dependency Check for {target_url}')
            scans_collection.insert_one({'url_id': url_id, 'scan_type': 'OWASP Dependency Check', 'status': 'In Progress'})
            owasp_result = owasp_dependency_check(target_url)
            scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'OWASP Dependency Check', 'result': owasp_result})
            scans_collection.update_one({'url_id': url_id, 'scan_type': 'OWASP Dependency Check'}, {'$set': {'status': 'Completed'}})
        
        except Exception as e:
            print(f'Error during CMS Identification for {target_url}: {e}')
            scans_collection.update_one({'url_id': url_id, 'scan_type': 'CMS Identification'}, {'$set': {'status': 'Failed'}})

       
    #Run CMS-specific scans based on identified CMS.
        try:
           if cms == 'WordPress':
            # WPScan
                print(f'Starting WPScan for {target_url}')
                scans_collection.insert_one({'url_id': url_id, 'scan_type': 'WPScan', 'status': 'In Progress'})
                wpscan_result = wpscan(target_url)
                if wpscan_result:
                    try:
                       result_json = json.loads(wpscan_result)
                       scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'WPScan', 'result': result_json})
                       scans_collection.update_one({'url_id': url_id, 'scan_type': 'WPScan'}, {'$set': {'status': 'Completed'}})
                    except json.JSONDecodeError as e:
                        print(f'JSON decoding error for WPScan results: {e}')
                        scans_collection.update_one({'url_id': url_id, 'scan_type': 'WPScan'}, {'$set': {'status': 'Failed'}})
                cmsmap_result = cmsmap(target_url, 'wordpress')
                scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'CMSMap', 'result': cmsmap_result})            
                    
           elif cms == 'Drupal':
            # Droopescan
                 print(f'Starting Droopescan for {target_url}')
                 scans_collection.insert_one({'url_id': url_id, 'scan_type': 'Droopescan', 'status': 'In Progress'})
                 droopescan_result = droopescan(target_url)
                 if droopescan_result:
                    try:
                     result_json = json.loads(droopescan_result)
                     scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'Droopescan', 'result': result_json})
                     scans_collection.update_one({'url_id': url_id, 'scan_type': 'Droopescan'}, {'$set': {'status': 'Completed'}})
                    except json.JSONDecodeError as e:
                     print(f'JSON decoding error for Droopescan results: {e}')
                     scans_collection.update_one({'url_id': url_id, 'scan_type': 'Droopescan'}, {'$set': {'status': 'Failed'}})
                 cmsmap_result = cmsmap(target_url, 'drupal')
                 scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'CMSMap', 'result': cmsmap_result})    
                    
           elif cms == 'Joomla':
            # Joomscan
                 print(f'Starting Joomscan for {target_url}')
                 scans_collection.insert_one({'url_id': url_id, 'scan_type': 'Joomscan', 'status': 'In Progress'})
                 joomscan_result = joomscan(target_url)
                 if joomscan_result:
                   try:
                     result_json = json.loads(joomscan_result)
                     scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'Joomscan', 'result': result_json})
                     scans_collection.update_one({'url_id': url_id, 'scan_type': 'Joomscan'}, {'$set': {'status': 'Completed'}})
                   except json.JSONDecodeError as e:
                      print(f'JSON decoding error for Joomscan results: {e}')
                      scans_collection.update_one({'url_id': url_id, 'scan_type': 'Joomscan'}, {'$set': {'status': 'Failed'}})  
                 cmsmap_result = cmsmap(target_url, 'joomla')
                 scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'CMSMap', 'result': cmsmap_result})

        # General Scans                
                    
        except Exception as e:
         print(f'Error during CMS-specific scans for {target_url}: {e}')

        # Nmap Scan
        try:
            print(f'Starting Nmap scan for {target_url}')
            scans_collection.insert_one({'url_id': url_id, 'scan_type': 'Nmap Scan', 'status': 'In Progress'})
            nmap_results = nmap_scan(target_url, cms)  # Pass the detected CMS to nmap_scan
            if nmap_results:
                for result in nmap_results:
                    scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'Nmap Scan', 'result': result})
                scans_collection.update_one({'url_id': url_id, 'scan_type': 'Nmap Scan'}, {'$set': {'status': 'Completed'}})
            else:
                scans_collection.update_one({'url_id': url_id, 'scan_type': 'Nmap Scan'}, {'$set': {'status': 'Failed'}})
        except Exception as e:
            print(f'Error during Nmap Scan for {target_url}: {e}')
            scans_collection.update_one({'url_id': url_id, 'scan_type': 'Nmap Scan'}, {'$set': {'status': 'Failed'}})
        
        # Metasploit Scan
        try:
            print(f'Starting Metasploit scan for {target_url}')
            scans_collection.insert_one({'url_id': url_id, 'scan_type': 'Metasploit Scan', 'status': 'In Progress'})
            metasploit_result = metasploit_scan(target_url)
            if metasploit_result:
                scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'Metasploit Scan', 'result': metasploit_result})
                scans_collection.update_one({'url_id': url_id, 'scan_type': 'Metasploit Scan'}, {'$set': {'status': 'Completed'}})
            else:
                scans_collection.update_one({'url_id': url_id, 'scan_type': 'Metasploit Scan'}, {'$set': {'status': 'Failed'}})
        except Exception as e:
            print(f'Error during Metasploit Scan for {target_url}: {e}')
            scans_collection.update_one({'url_id': url_id, 'scan_type': 'Metasploit Scan'}, {'$set': {'status': 'Failed'}})

        # ZAP Scans
        try:
            print(f'Starting ZAP scans for {target_url}')
            scans_collection.insert_one({'url_id': url_id, 'scan_type': 'ZAP Scan', 'status': 'In Progress'})
            start_spider(target_url)
            start_active_scan(target_url)
            start_passive_scan(target_url)

            zap_report_json, zap_alerts = generate_zap_reports(target_url)
            scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'ZAP Report', 'result': zap_report_json})
            scan_results_collection.insert_one({'url_id': url_id, 'scan_type': 'ZAP Alerts', 'result': zap_alerts})
            scans_collection.update_one({'url_id': url_id, 'scan_type': 'ZAP Scan'}, {'$set': {'status': 'Completed'}})
        except Exception as e:
            print(f'Error during ZAP Scans for {target_url}: {e}')
            scans_collection.update_one({'url_id': url_id, 'scan_type': 'ZAP Scan'}, {'$set': {'status': 'Failed'}})

        #DefectDojo Scans
        try:
           product_id = 1  # Adjust this to your DefectDojo product ID
           engagement_name = f"VAPT for {target_url} - {datetime.datetime.now().strftime('%Y-%m-%d')}"
           engagement_id = get_defectdojo_engagement(product_id, engagement_name)

           if engagement_id is None:
               print(f"Engagement {engagement_name} not found in DefectDojo. Creating a new engagement.")
            # Create the engagement if it doesn't exist
               engagement_id = create_defectdojo_engagement(product_id, engagement_name)

           elif engagement_id:
               test_id = create_defectdojo_test(engagement_id, target_url)
               if test_id:
                for scan_result in scan_result.values():
                 if scan_result:
                    description = json.dumps(scan_result, indent=4)
                    upload_defectdojo_finding(test_id, target_url, description)
                    print(f"Findings for {target_url} uploaded to DefectDojo.")

        except Exception as e:
            print(f'Error updating scan status for {target_url}: {e}')

        # Update URL scan status
        try:
            urls_collection.update_one({'_id': url_id}, {'$set': {'scan_status': 'Completed'}})
        except Exception as e:
            print(f'Error updating scan status for {target_url}: {e}')

    except Exception as e:
        print(f'Unexpected error during VAPT process for {target_url}: {e}')

if __name__ == "__main__":
    drop_collections()
    with open("/mnt/c/users/aryan/OneDrive/Desktop/Project/URL.csv", "r") as file:
        urls = [line.strip() for line in file if line.strip()]

    for target_url in urls:
        print(f'Processing {target_url}')
        try:
            subdomains = enumerate_subdomains(target_url)
        except Exception as e:
            print(f'Error enumerating subdomains for {target_url}: {e}')
            continue

        for subdomain in subdomains:
            if subdomain == "No names were discovered":
                break
            else: 
                try:
                    results = perform_vapt(subdomain)
                    print(f'VAPT results for {subdomain}: {results}')
                except Exception as e:
                    print(f'Error performing VAPT for subdomain {subdomain}: {e}')
                    continue

                # Store VAPT results in MongoDB
                try:
                    scans_collection.insert_one({
                        'url': target_url,
                        'subdomain': subdomain,
                        'results': results,
                        'timestamp': datetime.datetime.now()
                    })
                    print(f'Stored VAPT results for {subdomain} in MongoDB')
                except Exception as e:
                    print(f'Error storing VAPT results for {subdomain}: {e}')

    # Process top-level URLs
    for url in urls:
        print(f'Performing VAPT on {url}')
        try:
            results = perform_vapt(url)
            print(f'VAPT results for {url}: {results}')

            # Store VAPT results in MongoDB
            scans_collection.insert_one({
                'url': url,
                'results': results,
                'timestamp': datetime.datetime.now()
            })
            print(f'Stored VAPT results for {url} in MongoDB')
        except Exception as e:
            print(f'Error performing VAPT or storing results for {url}: {e}')
