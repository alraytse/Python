import paramiko
import difflib
import getpass

def ssh_and_capture_output(hostname, eid, password, filename):
    commands = [
        "term len 0",
        "sh ip bgp ipv4 unicast summary vrf all",
        "sh ip bgp neighbors vrf all | count",
        "sh ip bgp vrf all all | count",
        "sh ip arp | count",
        "sh ip arp",
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

        print(f"✅ Output written to {filename} for {hostname}")

    except Exception as e:
        print(f"❌ SSH connection to {hostname} failed: {e}")
    finally:
        client.close()

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

def main():
    raw_input = input("Enter hostnames (comma-separated): ")
    hostnames = [h.strip() for h in raw_input.split(',') if h.strip()]
    eid = input("Enter your EID (username): ").strip()
    password = getpass.getpass("Enter your password: ").strip()
    first_run = input("Is this the first run? (y/n): ").strip().lower()

    for hostname in hostnames:
        print(f"\n--- Processing {hostname} ---")
        if first_run == 'y':
            filename = f"{hostname}.before"
            ssh_and_capture_output(hostname, eid, password, filename)
        else:
            before_file = f"{hostname}.before"
            after_file = f"{hostname}.after"
            ssh_and_capture_output(hostname, eid, password, after_file)
            compare_file = f"{hostname}.compare"
            compare_files(before_file, after_file, compare_file)

if __name__ == "__main__":
    main()
