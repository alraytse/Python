import paramiko

# Configuration
vm_ip = "192.168.1.100"     # Replace with the VM's IP address
username = "your_username"  # Replace with SSH username
password = "your_password"  # Or use SSH keys instead

def get_linux_version(ip, user, passwd):
    try:
        # Create SSH session
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"[+] Connecting to {ip}...")
        ssh.connect(ip, username=user, password=passwd, timeout=10)

        # Run command to get Linux version
        stdin, stdout, stderr = ssh.exec_command("cat /etc/os-release")
        output = stdout.read().decode()
        error = stderr.read().decode()

        if error:
            print(f"[!] Error: {error}")
        else:
            print("[+] OS Version Info:")
            print(output)

        ssh.close()

    except Exception as e:
        print(f"[!] SSH connection failed: {e}")

if __name__ == "__main__":
    get_linux_version(vm_ip, username, password)
