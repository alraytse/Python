import shutil

INTERFACES_FILE = "/etc/network/interfaces"
BACKUP_FILE = "/etc/network/interfaces.bak"

def prompt_default(prompt, default):
    inp = input(f"{prompt} [{default}]: ").strip()
    return inp if inp else default

def create_static_config(iface, ip, netmask, gateway, dns=None):
    lines = [
        f"auto {iface}",
        f"iface {iface} inet static",
        f"    address {ip}",
        f"    netmask {netmask}",
        f"    gateway {gateway}"
    ]
    if dns:
        lines.append(f"    dns-nameservers {dns}")
    return lines

def modify_interfaces_file(iface, ip, netmask, gateway, dns):
    # Backup the original file
    shutil.copy2(INTERFACES_FILE, BACKUP_FILE)
    print(f"Backup of original file saved as {BACKUP_FILE}")

    with open(INTERFACES_FILE, "r") as f:
        lines = f.readlines()

    # Remove existing config for this iface (simple approach)
    inside_iface = False
    new_lines = []
    for line in lines:
        if line.strip().startswith(f"iface {iface} inet"):
            inside_iface = True
            continue
        if inside_iface:
            if line.strip() == "" or line.startswith("auto") or line.startswith("iface"):
                inside_iface = False
                # Don't skip this line, add it
                new_lines.append(line)
            else:
                # Skip lines inside the iface config block
                continue
        if not inside_iface:
            new_lines.append(line)

    # Add new static config at the end
    new_lines.append("\n")
    new_lines.extend(line + "\n" for line in create_static_config(iface, ip, netmask, gateway, dns))

    with open(INTERFACES_FILE, "w") as f:
        f.writelines(new_lines)

    print(f"Updated {INTERFACES_FILE} with static IP config for {iface}")

def main():
    print("Modify /etc/network/interfaces to set static IP")

    iface = input("Interface name (e.g., eth0): ").strip()
    ip = input("Static IP address (e.g., 192.168.1.100): ").strip()
    netmask = input("Netmask (e.g., 255.255.255.0): ").strip()
    gateway = input("Gateway IP (e.g., 192.168.1.1): ").strip()
    dns = input("DNS servers (space-separated, optional): ").strip()

    modify_interfaces_file(iface, ip, netmask, gateway, dns if dns else None)

if __name__ == "__main__":
    main()
