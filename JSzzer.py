import re
import requests

def extract_sensitive_info(content):
    # Define various patterns for different types of sensitive information
    patterns = {
        'Email Addresses': re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
        'IP Addresses': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'URLs': re.compile(r'(https?://[^\s]+)'),
        'Phone Numbers': re.compile(r'\b(?:\+?(\d{1,3})?[-. \(\)]*)?(\d{1,4})[-. \(\)]*(\d{1,4})[-. \(\)]*(\d{1,9})\b'),
        'API Keys': re.compile(r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)["\']?'),
        'Access Tokens': re.compile(r'(?i)access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)["\']?'),
        'Authorization Headers': re.compile(r'(?i)authorization["\']?\s*[:=]\s*["\']?Bearer\s+([a-zA-Z0-9_\-]+)["\']?'),
        'Credit Card Numbers': re.compile(r'\b(?:\d[ -]*?){13,16}\b'),
        'Social Security Numbers': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'AWS Access Key ID': re.compile(r'(?i)aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?'),
        'AWS Secret Access Key': re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        'Database Connection Strings': re.compile(r'(?i)(jdbc|mongodb|mysql|postgres|oracle|sqlserver):\/\/[^\s]+'),
        'Private Keys': re.compile(r'-----BEGIN (RSA|DSA|EC|PGP|OPENSSH|ENCRYPTED) PRIVATE KEY-----'),
        'Sensitive Configurations': re.compile(r'(?i)(password|passwd|pwd|secret)["\']?\s*[:=]\s*["\']?([^\s"\']+)["\']?'),
        'OAuth Client Secrets': re.compile(r'(?i)client[_-]?secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)["\']?'),
        'JWT Tokens': re.compile(r'eyJ[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+'),
        'Google API Keys': re.compile(r'AIza[0-9A-Za-z-_]{35}'),
        'Heroku API Keys': re.compile(r'(?i)heroku[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)["\']?'),
        'Slack Webhooks': re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9_\/]+'),
        'Stripe API Keys': re.compile(r'sk_live_[0-9a-zA-Z]{24}'),
        'Firebase Database URLs': re.compile(r'https://[a-zA-Z0-9_-]+\.firebaseio\.com'),
        'Private SSH Keys': re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        'GitHub Personal Access Tokens': re.compile(r'ghp_[A-Za-z0-9_]{36}'),
        'Google Cloud Project IDs': re.compile(r'(?i)google[_-]?cloud[_-]?project["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)["\']?'),
        'Twilio API Keys': re.compile(r'SK[0-9a-fA-F]{32}'),
        'SendGrid API Keys': re.compile(r'SG\.[A-Za-z0-9_\-]+'),
        'Facebook Access Tokens': re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'),
        'GitLab Personal Access Tokens': re.compile(r'glpat-[0-9a-zA-Z\-_]{20}'),
        'Amazon MWS Keys': re.compile(r'(?i)mws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?'),
        'PayPal API Keys': re.compile(r'(?i)paypal[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{32})["\']?'),
        'Mailchimp API Keys': re.compile(r'(?i)mailchimp[_-]?api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9]{32})["\']?'),
        'Slack Tokens': re.compile(r'xox[abp]-[A-Za-z0-9-]{10,48}'),
        'Azure Storage Account Keys': re.compile(r'(?i)azure[_-]?storage[_-]?account[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9+\/=]{64})["\']?'),
        'Salesforce OAuth Tokens': re.compile(r'00D[A-Za-z0-9]{15,18}\![A-Za-z0-9\._\-]{80,130}'),
        'Shopify Private App Keys': re.compile(r'shpss_[a-fA-F0-9]{32}'),
        'Dropbox Access Tokens': re.compile(r'sl\.[A-Za-z0-9_\-]{60}'),
        'Azure Service Principal Secrets': re.compile(r'(?i)azure[_-]?service[_-]?principal[_-]?secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{36,})["\']?'),
        'DigitalOcean Personal Access Tokens': re.compile(r'dop_v1_[a-z0-9]{64}'),
        'GitHub OAuth Secrets': re.compile(r'(?i)github[_-]?oauth[_-]?secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]+)["\']?'),
        'WordPress Database Credentials': re.compile(r'(?i)(DB_PASSWORD|DB_USER|DB_HOST)["\']?\s*[:=]\s*["\']?([^\s"\']+)["\']?'),
        'Docker Hub Access Tokens': re.compile(r'(?i)docker[_-]?hub[_-]?token["\']?\s*[:=]\s*["\']?([A-Za-z0-9-]{36})["\']?')
    }
    
    # Iterate through patterns and search content
    for label, pattern in patterns.items():
        matches = pattern.findall(content)
        if matches:
            print(f"{label} found:")
            for match in matches:
                print(match)
            print()

def get_content_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return None

def get_content_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad status codes
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching the URL: {e}")
    return None

if __name__ == "__main__":
    # Get input from the user (file path or URL)
    user_input = input("Enter the path to the JavaScript file or a URL: ")
    
    # Check if input is a URL or a file path
    if user_input.startswith('http://') or user_input.startswith('https://'):
        content = get_content_from_url(user_input)
    else:
        content = get_content_from_file(user_input)
    
    if content:
        extract_sensitive_info(content)

