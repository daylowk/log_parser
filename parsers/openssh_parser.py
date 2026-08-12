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

EVENT_PATTERN = {
    'accepted': re.compile(r'Accepted\spassword'),
    'invalid': re.compile(r'Invalid\suser', re.IGNORECASE),
    'failure': re.compile(r'failures?(?:\sfor|;\slogname)'),
    'failed': re.compile(r'Failed', re.IGNORECASE),
    'repeated': re.compie(r'\bmessage\srepeated\s(\d+)')
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
        user_match = pattern.search(log_line)

        if user_match:
            return user_match.group()

def event_type_capture(log_line):
    for event_type, pattern in EVENT_PATTERN.items():
        type_pattern_match = pattern.search(log_line)

        if type_pattern_match: 
            return event_type
        
    return 'Other'

def record_attempts(ip, user, event_type, timestamp, password_attempts):
    if event_type not in ('failed', 'repeated'):
        return
    
    if ip not in password_attempts:
        password_attempts[ip] = []

    password_attempts[ip].append({
        'user': user,
        'timestamp': timestamp,
        'event': event_type
    })



total = 0
first_timestamp = None
last_timestamp = None
ips = {}
lines_without_ip = 0
users = {}
password_attempts = {}

BRUTE_FORCE_THRESHOLD = 5

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

        event = event_type_capture(line)
        if ip:
            record_attempts(ip, user, event, timestamp, password_attempts)

for ip, attempts in password_attempts.items():
    if len(attempts) >= BRUTE_FORCE_THRESHOLD:
        print(f'Possible brute force attempt from {ip}: {len(attempts)} failed attempts')

print(f'Total of lines: {total}')
print(f'First timestamp: {first_timestamp}')
print(f'Last timestamp: {last_timestamp}')
ips = sorted(ips.items(), key=lambda item: item[1], reverse=True)
for ip, counter in ips:
    print(f'{ip}: {counter}')
print(f'Lines without IP: {lines_without_ip}')
print(users)