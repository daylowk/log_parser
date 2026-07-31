import re

timestamp_pattern = re.compile(r'\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}')

total = 0
first_timestamp = None

with open('log_samples/OpenSSH_2k.log', 'r') as arquivo:
    for linha in arquivo:
        total += 1

        timestamp = timestamp_pattern.search(linha).group()

        if first_timestamp is None:
            first_timestamp = timestamp
            
        last_timestamp = timestamp

print(f'Total de linhas: {total}')
print(f'Primeiro timestamp: {first_timestamp}')
print(f'Último timestamp: {last_timestamp}')