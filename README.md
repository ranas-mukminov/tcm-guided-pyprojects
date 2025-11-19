# TCM Guided Python Security Projects

**<a href="README.md">🇬🇧 English</a>** | **<a href="README.ru.md">🇷🇺 Русский</a>**

[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](SECURITY_AUDIT_ISSUES.md)
[![Code Quality](https://img.shields.io/badge/code%20quality-PEP%208-blue.svg)](https://www.python.org/dev/peps/pep-0008/)
[![Python Version](https://img.shields.io/badge/python-3.7%2B-brightgreen.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Educational-orange.svg)](LICENSE)

**Production-ready** | **Educational** | **PEP 8 Compliant** | **Security-First**

A collection of Python security tools and scripts for educational purposes and authorized penetration testing.

[Detailed Manual](MANUAL.md) | [Русское руководство](MANUAL.ru.md)

---

## 🎯 Professional Security Testing & Infrastructure Services

Looking for **production-grade security infrastructure** or **professional DevOps & pentesting assistance**?

**[run-as-daemon.ru](https://run-as-daemon.ru)** — Professional DevOps, System Administration & Security Services

**Services:**
- 🔒 **Security Testing**: Authorized penetration testing, vulnerability assessments
- 🏗️ **Production Infrastructure**: Docker, Kubernetes, Nomad orchestration
- 🛡️ **Security-First Architecture**: "Defense by design. Speed by default"
- 🔧 **System Administration**: Linux/Windows server management, automation
- 🌐 **Network Security**: VPN solutions, firewall configuration, network hardening
- 🚀 **DevOps & Automation**: CI/CD pipelines, deployment automation
- ⚡ **High-Load Systems**: Performance optimization, scalability solutions

**Contact:** [run-as-daemon.ru](https://run-as-daemon.ru)

---

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

## 🏗️ Production Deployment

**Need production-grade security infrastructure?**

These educational tools demonstrate security concepts, but **production environments require professional hardening**.

For production deployments:
- **Authorized penetration testing** of your infrastructure
- **Security architecture design** from the ground up
- **Infrastructure orchestration** (Docker, Kubernetes, Nomad)
- **Server hardening** and security configuration
- **High-availability** and load-balanced systems

See a production example: [SMM Bot](https://github.com/ranas-mukminov/smm_bot) - A professionally deployed Telegram bot with enterprise-grade infrastructure.

**Professional assistance:** [run-as-daemon.ru](https://run-as-daemon.ru)

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

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

---

## 👨‍💻 Author & Professional Services

**Ranas Mukminov** — DevOps Engineer, Security Researcher & System Administrator

Based in Innopolis, Tatarstan, Russia. Specializing in security infrastructure, professional pentesting, and production-grade DevOps solutions.

### 🔒 Security & Penetration Testing
- Authorized penetration testing and vulnerability assessments
- Security audits for web applications and infrastructure
- Exploit development and security research
- CTF competitions and security training

### 🏗️ Infrastructure & Orchestration
- Docker, Kubernetes, Nomad container orchestration
- Multi-server architecture design and implementation
- Load balancing and high-availability systems
- Geographic distribution and failover configuration

### 🛡️ Security & Server Hardening
- Linux/Windows server security hardening
- Firewall configuration (iptables, fail2ban)
- VPN solutions (WireGuard, OpenVPN, SSH tunnels)
- Security monitoring and intrusion detection

### 🔧 System Administration
- Linux (Ubuntu, Debian) and Windows Server administration
- Database management (PostgreSQL, MySQL, Redis)
- Backup and disaster recovery systems
- Performance optimization and troubleshooting

### 🌐 Network Security
- Network topology design and implementation
- OpenWRT router configuration
- Secure networking and segmentation
- VPN and tunnel management

### 🚀 Automation & DevOps
- CI/CD pipeline design and implementation
- Infrastructure as Code (IaC)
- Automated deployment and monitoring
- Git workflow and version control

### ⚡ High-Load Systems
- Performance optimization and caching (Redis)
- Load balancing and reverse proxy (Nginx, Traefik)
- Scalability planning and implementation
- Multi-region deployment strategies

### 📞 Professional Services Contact

- **Website:** [run-as-daemon.ru](https://run-as-daemon.ru)
- **Location:** Innopolis, Tatarstan, Russia
- **Status:** Individual Entrepreneur (ИП)
- **GitHub:** [@ranas-mukminov](https://github.com/ranas-mukminov)

---

## 💼 Professional Support

For production deployments, security audits, or infrastructure consulting:
- **Professional pentesting** and security assessments
- **Infrastructure design** and implementation
- **24/7 monitoring** and support available
- **SLA-backed services** for mission-critical systems

Contact: [run-as-daemon.ru](https://run-as-daemon.ru)

---

## 🌟 Community Support

For educational questions and community support:
- Open an [Issue](https://github.com/ranas-mukminov/tcm-guided-pyprojects/issues)
- Contribute via [Pull Requests](https://github.com/ranas-mukminov/tcm-guided-pyprojects/pulls)
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)

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

## 🔗 Related Projects

- [SMM Bot](https://github.com/ranas-mukminov/smm_bot) — Production-grade Telegram bot (professional deployment reference)
- [TCM Security Academy](https://academy.tcm-sec.com/)
- [Python for Pentesters](https://github.com/topics/python-pentesting)
- [Awesome Penetration Testing](https://github.com/enaqx/awesome-pentest)

---

**Remember**: Always practice ethical hacking. Only test systems you have permission to assess.

**Production infrastructure and professional security testing:** [run-as-daemon.ru](https://run-as-daemon.ru)
