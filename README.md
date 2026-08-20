    # OpenSSH Log Parser

This is a command-line tool for analyzing OpenSSH logs and extracting information such as IP addresses, users and event types.

## Features

- Extract and count IP addresses
- Extract and count usernames
- Identify event types (Accepted password, failed password, etc.)
- Display the top IP addresses and users
- Output results as text or JSON

## Requirements

- Python 3.x
- No external dependencies

## Installation

Just clone the repository:
```bash
git clone https://github.com/daylowk/log_parser
cd log_parser
```

## Usage

Simple example:
```bash
python3 parser/openssh_parser.py /path/to/log
```
To control how many IPs and users it lists:
```bash
python3 parser/openssh_parser.py -t 10 /path/to/log
```
To export into a JSON file:
```bash
python3 parser/openssh_parser.py -t 10 /path/to/log -o json > file.json
```

Example with output:
```bash
python3 parser/openssh_parser.py log_sample/OpenSSH_2k.log
```
```bash
========================================
OpenSSH Log Parser
========================================

Log Information
----------------------------------------
Total lines: 2000
First Timestamp: Dec 10 06:55:46
Last timestamp: Dec 10 11:04:45
Lines without IP: 266

Top IP addresses
----------------------------------------
183.62.140.253: 867
187.141.143.180: 349
103.99.0.122: 172
112.95.230.3: 80
5.188.10.180: 53

Top Users
----------------------------------------
root: 751
admin: 88
support: 18
oracle: 18
test: 15

Event Types
----------------------------------------
invalid user: 365
failure warning: 507
failed password: 393
accepted password: 1
```

## Credits and Notes

- This parser was designed for OpenSSH logs following the format in log_sample/OpenSSH_2k.log_templates.csv.

- The OpenSSH log sample and template used for development and testing was obtained from LogPAI, Loghub (https://github.com/logpai/loghub)