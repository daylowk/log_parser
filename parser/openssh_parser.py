import re
import ipaddress
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument(
    'logfile',
    metavar='LOGFILE',
    help='Path to the OpenSSH log file.'
)
parser.add_argument(
    '-t',
    '--top',
    type=int,
    default=5,
    help='Number of top IPs and users to display.'
)
parser.add_argument(
    '-o',
    '--output',
    choices=['text', 'json'],
    default='text',
    help='Output format.'
)
args = parser.parse_args()

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
    'accepted password': re.compile(r'Accepted\spassword'),
    'invalid user': re.compile(r'Invalid\suser', re.IGNORECASE),
    'failure warning': re.compile(r'failures?(?:\sfor|;\slogname)'),
    'repeated': re.compile(r'\bmessage\srepeated\s(\d+)'),
    'failed password': re.compile(r'Failed')
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
            
            return event_type, type_pattern_match

    return 'Other', None

def build_results(total: int, first_timestamp: str, last_timestamp:str, ips: dict, lines_without_ip: int, users:dict, events: dict):
    ips = sorted(ips.items(), key=lambda item: item[1], reverse=True)
    users = sorted(users.items(), key=lambda item: item[1], reverse=True)

    return {
        'total_lines': total,
        'first_timestamp': first_timestamp,
        'last_timestamp': last_timestamp,
        'lines_without_ip': lines_without_ip,
        'top_ips': dict(ips[:args.top]),
        'top_users': dict(users[:args.top]),
        'events': events
    }

def display_text(results):
    print('========================================')
    print('OpenSSH Log Parser')
    print('========================================')
    print()
    print('Log Information')
    print('----------------------------------------')
    print(f'Total lines: {results['total_lines']}')
    print(f'First Timestamp: {results['first_timestamp']}')
    print(f'Last timestamp: {results['last_timestamp']}')
    print(f'Lines without IP: {results['lines_without_ip']}')
    print()
    print('Top IP addresses')
    print('----------------------------------------')
    for ip, counter in results['top_ips'].items():
        print(f'{ip}: {counter}')
    print()
    print('Top Users')
    print('----------------------------------------')
    for user, counter in results['top_users'].items():
            print(f'{user}: {counter}')
    print()
    print('Event Types')
    print('----------------------------------------')
    for event, counter in results['events'].items():
        print(f'{event}: {counter}')

def display_json(results):
    print(json.dumps(results, indent=4))

total = 0
first_timestamp = None
last_timestamp = None
ips = {}
lines_without_ip = 0
users = {}
events = {}

with open(args.logfile, 'r') as log_file:
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

        event_type, event_match = event_type_capture(line)
        if event_type != 'Other':
            if event_type == 'repeated':
                events['failed password'] = events.get('failed password', 0) + int(event_match.group(1))
                users[user] = users.get(user) + int(event_match.group(1)) - 1
            else:
                events[event_type] = events.get(event_type, 0) + 1

results = build_results(total, first_timestamp, last_timestamp, ips, lines_without_ip, users, events)

if args.output == 'json':
    display_json(results)
else:
    display_text(results)