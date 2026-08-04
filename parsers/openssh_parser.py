import re
import ipaddress

timestamp_pattern = re.compile(r'\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}')
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
total = 0
first_timestamp = None
ips = {}

with open('log_samples/OpenSSH_2k.log', 'r') as arquivo:
    for linha in arquivo:
        total += 1
        timestamp_match = timestamp_pattern.search(linha)
        ip_match = ip_pattern.search(linha)

        if timestamp_match:
            timestamp = timestamp_match.group()
            if first_timestamp is None:
                first_timestamp = timestamp          
            last_timestamp = timestamp

        if ip_match:
            ip = ip_match.group()
            try:
                ipaddress.IPv4Address(ip)
                ips[ip] = ips.get(ip, 0) + 1
            except ipaddress.AddressValueError:
                continue
        else:
            ips['Sem IP'] = ips.get('Sem IP', 0) + 1

print(f'Total de linhas: {total}')
print(f'Primeiro timestamp: {first_timestamp}')
print(f'Último timestamp: {last_timestamp}')
for ip, counter in ips.items():
    print(f'{ip}: {counter}')