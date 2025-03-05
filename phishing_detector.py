import re
import urllib.parse
import socket
import requests
from collections import defaultdict

def analyze_url(url):
    analysis = defaultdict(str)
    risk_score = 0
    
    try:
        # Parse URL components
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urllib.parse.urlparse(url)
        
        # Feature 1: URL Length
        analysis['url_length'] = len(url)
        if len(url) > 75:
            risk_score += 1
            
        # Feature 2: Subdomain Count
        subdomains = parsed.netloc.split('.')
        analysis['subdomain_count'] = len(subdomains) - 2  # Subtract main domain and TLD
        if analysis['subdomain_count'] > 2:
            risk_score += 1
            
        # Feature 3: Using IP Address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        analysis['is_ip'] = bool(re.match(ip_pattern, parsed.netloc))
        if analysis['is_ip']:
            risk_score += 2
            
        # Feature 4: Non-Standard Port
        analysis['port'] = parsed.port
        if parsed.port and parsed.port not in [80, 443]:
            risk_score += 1
            
        # Feature 5: URL Shortener
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'is.gd', 'buff.ly', 't.co']
        analysis['is_shortener'] = any(s in parsed.netloc for s in shorteners)
        if analysis['is_shortener']:
            risk_score += 2
            
        # Feature 6: '@' Symbol
        analysis['has_at_symbol'] = '@' in url
        if analysis['has_at_symbol']:
            risk_score += 2
            
        # Feature 7: Double Slashes
        analysis['double_slashes'] = '//' in parsed.path
        if analysis['double_slashes']:
            risk_score += 1
            
        # Feature 8: HTTPS in Domain
        analysis['https_in_domain'] = 'https' in parsed.netloc.lower()
        if analysis['https_in_domain']:
            risk_score += 1
            
        # Feature 9: Suspicious Keywords
        keywords = ['login', 'secure', 'account', 'verify', 'signin', 'update']
        analysis['suspicious_keywords'] = [k for k in keywords if k in parsed.path.lower()]
        if analysis['suspicious_keywords']:
            risk_score += len(analysis['suspicious_keywords'])
            
        # Feature 10: HTTPS Usage
        try:
            response = requests.head(url.replace('http://', 'https://', 1), timeout=5)
            analysis['uses_https'] = response.ok
        except:
            analysis['uses_https'] = False
        if not analysis['uses_https']:
            risk_score += 1
            
    except Exception as e:
        print(f"Error analyzing URL: {str(e)}")
        return None
    
    return {
        'risk_score': risk_score,
        'analysis': dict(analysis),
        'is_phishing': risk_score >= 5
    }

def print_results(results):
    print("\nPhishing Analysis Results:")
    print(f"Total Risk Score: {results['risk_score']}/15")
    print(f"Verdict: {'Phishing Detected' if results['is_phishing'] else 'Likely Safe'}\n")
    
    print("Detailed Analysis:")
    for key, value in results['analysis'].items():
        print(f"{key.replace('_', ' ').title()}: {value}")

if __name__ == "__main__":
    url = input("Enter URL to analyze: ").strip()
    results = analyze_url(url)
    
    if results:
        print_results(results)
    else:
        print("Failed to analyze the URL")
