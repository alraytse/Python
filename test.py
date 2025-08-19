import re
import subprocess
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import paramiko
import difflib
import getpass

# Extract IPs from files
def extract_ips_from_file(filename):
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ipv6_pattern = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b')
    ips = []
    try:
        with open(filename.strip(), 'r') as file:
            for line in file:
                ips.extend(ipv4_pattern.findall(line))
                ips.extend(ipv6_pattern.findall(line))
    except FileNotFoundError:
        print(f"File not found: {filename}")
    return ips

# Ping IP with retries
def ping_ip(ip, retries=3):
    for attempt in range(1, retries + 1):
        try:
            ping_cmd = ['ping', '-c', '10', ip] if ':' not in ip else ['ping6', '-c', '10', ip]
            result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            if result.returncode == 0:
                return ip, "Success", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                time.sleep(1)
        except Exception as e:
            return ip, f"Error: {str(e)}", datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return ip, "Failure", datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# SSH and capture output
def ssh_and_capture_output(hostname, eid, password, filename):
    commands = [
        "term len 0",
        "sh ip bgp ipv4 unicast summary vrf all",
        "sh ip bgp neighbors vrf all | count",
        "sh ip bgp vrf all all | count",
        "sh ip arp vrf all | count",
        "sh ip arp vrf all",
        "sh ip eigrp neighbors",
        "sh ip route eigrp",
        "sh mac address-table",
        "sh running"
    ]

    output_lines = []

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=eid, password=password, look_for_keys=False)

        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            output = stdout.read().decode()
            output_lines.append(f"\n=== {cmd} ===\n{output.strip()}")

        with open(filename, "w") as f:
            f.write('\n'.join(output_lines))

        return f"✅ Output written to {filename} for {hostname}"

    except Exception as e:
        return f"❌ SSH connection to {hostname} failed: {e}"
    finally:
        client.close()

# Compare before/after files
def compare_files(file1, file2, output_file):
    try:
        with open(file1, 'r') as f1, open(file2, 'r') as f2:
            diff = difflib.unified_diff(
                f1.readlines(),
                f2.readlines(),
                fromfile=file1,
                tofile=file2
            )
            diff_output = ''.join(diff)
            if diff_output:
                with open(output_file, 'w') as outf:
                    outf.write(diff_output)
                print(f"📄 Differences for {file1} vs {file2} written to: {output_file}")
            else:
                print(f"✅ No differences between {file1} and {file2}")
    except FileNotFoundError:
        print(f"❌ Missing file(s): {file1} or {file2}")

# Run SSH in parallel
def run_ssh_parallel(hostnames, eid, password, first_run):
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for hostname in hostnames:
            filename = f"{hostname}.before" if first_run == 'y' else f"{hostname}.after"
            futures[executor.submit(ssh_and_capture_output, hostname, eid, password, filename)] = hostname

        for future in as_completed(futures):
            result = future.result()
            print(result)
            results.append(result)

    return results

# Main function
def main():
    # IP pinging section
    file_input = input("Enter file names to extract IPs (comma-separated): ")
    file_list = file_input.split(',')

    all_ips = []
    for file_name in file_list:
        all_ips.extend(extract_ips_from_file(file_name))

    all_ips = list(set(all_ips))  # Remove duplicates
    print(f"🔍 Starting parallel ping for {len(all_ips)} IPs...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(ping_ip, ip) for ip in all_ips]
        with open('ip.csv', 'w') as output_file:
            output_file.write("Timestamp,IP Address,Status\n")
            for future in tqdm(as_completed(futures), total=len(futures), desc="Pinging IPs"):
                ip, status, timestamp = future.result()
                output_file.write(f"{timestamp},{ip},{status}\n")

    print(f"✅ Ping results saved to ip.csv.")

    # SSH and comparison section
    raw_input = input("Enter hostnames (comma-separated): ")
    hostnames = [h.strip() for h in raw_input.split(',') if h.strip()]
    eid = input("Enter your EID (username): ").strip()
    password = getpass.getpass("Enter your password: ").strip()
    first_run = input("Is this the first run? (y/n): ").strip().lower()

    run_ssh_parallel(hostnames, eid, password, first_run)

    if first_run != 'y':
        for hostname in hostnames:
            before_file = f"{hostname}.before"
            after_file = f"{hostname}.after"
            compare_file = f"{hostname}.compare"
            compare_files(before_file, after_file, compare_file)

if __name__ == "__main__":
    main()
