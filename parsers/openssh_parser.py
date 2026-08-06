import re
import ipaddress

TIMESTAMP_PATTERN = re.compile(r'\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

USER_PATTERNS = {
    'accepted_password': re.compile(r'(?<=Accepted\spassword\sfor\s)\S+'),
    'too_many_auth_failures': re.compile(r'(?<=Disconnecting:\sToo\smany\sauthentication\sfailures\sfor\s)\S+'),
    'failed_password': re.compile(r'(?<=Failed\spassword\sfor\s)\S+(?=\sfrom)'),
    'invalid_user': re.compile(r'(?<=Invalid\suser\s)\S+', re.IGNORECASE),
    'user_equal': re.compile(r'(?<=user=)\S+'),
    'session_closed': re.compile(r'(?<=session\s(?:closed|opened)\sfor\suser\s)\S+')
}

def timestamp_capture(log_line):
    timestamp_match = TIMESTAMP_PATTERN.search(log_line)
            
    if timestamp_match:
        return timestamp_match.group()         

def ip_capture(log_line):
    ip_match = IP_PATTERN.search(log_line)
    
    if ip_match:
        ip = ip_match.group()
        try:
            ipaddress.IPv4Address(ip)
            return ip
        except ipaddress.AddressValueError:
            return None
    else:
        return None       

def user_capture(log_line):
    for pattern in USER_PATTERNS.values():
        match = pattern.search(log_line)

        if match:
            return match.group()

total = 0
first_timestamp = None
last_timestamp = None
ips = {}
lines_without_ip = 0
users = {}

with open('log_samples/OpenSSH_2k.log', 'r') as log_file:
    for line in log_file:
        total += 1

        timestamp = timestamp_capture(line)
        if first_timestamp is None:
                first_timestamp = timestamp  
        last_timestamp = timestamp

        ip = ip_capture(line)
        if ip:
            ips[ip] = ips.get(ip, 0) + 1 
        else:
            lines_without_ip += 1

        user = user_capture(line)
        if user: 
            users[user] = users.get(user, 0) + 1

print(f'Total of lines: {total}')
print(f'First timestamp: {first_timestamp}')
print(f'Last timestamp: {last_timestamp}')
for ip, counter in ips.items():
    print(f'{ip}: {counter}')
print(f'Lines without IP: {lines_without_ip}')
print(users)