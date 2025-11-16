# TCM Guided Python Security Projects

A collection of Python security tools and scripts for educational purposes and authorized penetration testing.

[Русская версия](README.ru.md) | [Detailed Manual](MANUAL.md)

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

These tools are designed for:
- Authorized security testing and penetration testing
- Educational and learning purposes
- Capture The Flag (CTF) competitions
- Security research in controlled environments

**NEVER use these tools on systems you do not own or have explicit permission to test.**

Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of these tools.

---

## 📋 Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Tools Overview](#tools-overview)
- [Quick Start](#quick-start)
- [Security Improvements](#security-improvements)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

- **Network Scanning**: Multi-threaded port scanner
- **Password Analysis**: Advanced password strength checker
- **Hash Cracking**: SHA256 dictionary attack tool
- **SQL Injection**: Blind SQL injection exploitation tools
- **SSH Brute Force**: SSH password brute forcing utility
- **Web Authentication**: HTTP login form brute forcing
- **Binary Exploitation**: Buffer overflow exploit examples

All tools include:
- ✅ Comprehensive error handling
- ✅ PEP 8 compliant code
- ✅ Detailed documentation
- ✅ Educational warnings
- ✅ Production-ready improvements

---

## 🔧 Requirements

### Python Version
- Python 3.7 or higher

### Dependencies

```bash
# Core dependencies
pip install requests paramiko pwntools

# Or install all at once
pip install -r requirements.txt
```

### Optional Tools
- **rockyou.txt**: Password wordlist for hash cracking
- **ssh-common-passwords.txt**: Password list for SSH brute forcing
- **top-100.txt**: Common passwords for web login attacks

---

## 📥 Installation

1. **Clone the repository**
```bash
git clone https://github.com/ranas-mukminov/tcm-guided-pyprojects.git
cd tcm-guided-pyprojects
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Make scripts executable (Linux/Mac)**
```bash
chmod +x *.py
```

4. **Verify installation**
```bash
python3 --version
python3 -c "import requests, paramiko; print('Dependencies OK')"
```

---

## 🛠️ Tools Overview

### 1. Host Scanner (`host_scanner.py`)
Multi-threaded port scanner with efficient resource management.
- Scans all 65,535 ports
- Uses ThreadPoolExecutor (100 workers)
- Real-time port discovery
```bash
python3 host_scanner.py <target>
```

### 2. Password Strength Checker (`passwd-strength.py`)
Comprehensive password validation tool.
- Length validation
- Character complexity checks
- Common pattern detection
- Repeated character detection
```bash
python3 passwd-strength.py
```

### 3. SHA256 Cracker (`sha256_cracking.py`)
Dictionary attack tool for SHA256 hashes.
```bash
python3 sha256_cracking.py <hash>
```

### 4. SQL Injection Exploits
Two variants for blind SQL injection:
- `sql_injection_exploit.py`: Basic linear search
- `exp_restrict_sql_injection.py`: Optimized with binary search
```bash
python3 sql_injection_exploit.py
```

### 5. SSH Brute Forcer (`ssh_login_brute_forcing.py`)
SSH password brute forcing tool with MITM warnings.
```bash
python3 ssh_login_brute_forcing.py
```

### 6. Web Login Brute Forcer (`web_login_form_brute_forcing.py`)
HTTP POST login form brute forcing utility.
```bash
python3 web_login_form_brute_forcing.py
```

### 7. Buffer Overflow Exploit (`buffer_overflow.py`)
Educational buffer overflow exploitation example.
```bash
python3 buffer_overflow.py
```

---

## 🚀 Quick Start

### Example 1: Scan a Host
```bash
python3 host_scanner.py 192.168.1.1
```

### Example 2: Check Password Strength
```bash
python3 passwd-strength.py
# Enter password when prompted
```

### Example 3: Crack SHA256 Hash
```bash
# First, create a hash to crack
echo -n "password123" | sha256sum

# Then crack it
python3 sha256_cracking.py ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

---

## 🔒 Security Improvements

This project has undergone comprehensive security and code quality improvements:

### Critical Fixes
- ✅ Fixed 15+ syntax errors across multiple files
- ✅ Corrected undefined function calls
- ✅ Replaced non-existent library functions
- ✅ Fixed resource exhaustion issues (65k threads → 100)

### Security Enhancements
- ✅ Added MITM vulnerability warnings
- ✅ Comprehensive network error handling
- ✅ Input validation
- ✅ Proper exception handling
- ✅ Timeout configurations

### Code Quality
- ✅ PEP 8 compliance (4-space indentation)
- ✅ Complete docstrings for all functions
- ✅ Type hints and parameter documentation
- ✅ Educational purpose warnings
- ✅ Improved logging and user feedback

See [SECURITY_AUDIT_ISSUES.md](SECURITY_AUDIT_ISSUES.md) for detailed audit report.

---

## 📚 Documentation

- **[Detailed Manual](MANUAL.md)**: Complete usage guide with examples
- **[Security Audit Report](SECURITY_AUDIT_ISSUES.md)**: Full vulnerability analysis
- **[Русское руководство](MANUAL.ru.md)**: Подробное руководство на русском

---

## 🤝 Contributing

Contributions are welcome! Please ensure:
1. Code follows PEP 8 guidelines
2. All functions have docstrings
3. Security warnings are included where appropriate
4. Tools remain educational in nature

---

## 📖 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PwnTools Documentation](https://docs.pwntools.com/)
- [Paramiko Documentation](http://docs.paramiko.org/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)

---

## 📝 License

This project is intended for educational purposes. Use responsibly and only on systems you own or have explicit permission to test.

---

## 👨‍💻 Author

**TCM Security Training Projects**

For issues or questions, please open an issue on GitHub.

---

## 🔗 Related Projects

- [TCM Security Academy](https://academy.tcm-sec.com/)
- [Python for Pentesters](https://github.com/topics/python-pentesting)
- [Awesome Penetration Testing](https://github.com/enaqx/awesome-pentest)

---

**Remember**: Always practice ethical hacking. Only test systems you have permission to assess.
