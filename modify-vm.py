def prompt_modify(field_name, current_value):
    print(f"{field_name} (current: {current_value})")
    new_value = input(f"Enter new {field_name} (press Enter to keep current): ").strip()
    return new_value if new_value else current_value

def main():
    # Default values from example
    iface = "en0"
    inet = "192.168.1.100"
    netmask = "0xffffff00"
    broadcast = "192.168.1.255"

    print("Modify the following interface details or press Enter to keep defaults:")

    iface_new = prompt_modify("Interface name", iface)
    inet_new = prompt_modify("inet IP address", inet)
    netmask_new = prompt_modify("netmask", netmask)
    broadcast_new = prompt_modify("broadcast IP address", broadcast)

    print("\n--- Before modification ---")
    print(f"Interface: {iface}")
    print(f"inet: {inet}")
    print(f"netmask: {netmask}")
    print(f"broadcast: {broadcast}")

    print("\n--- After modification ---")
    print(f"Interface: {iface_new}")
    print(f"inet: {inet_new}")
    print(f"netmask: {netmask_new}")
    print(f"broadcast: {broadcast_new}")

    # Write to file
    with open("interface_config.txt", "w") as f:
        f.write(f"{iface_new}: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n")
        f.write(f"\tinet {inet_new} netmask {netmask_new} broadcast {broadcast_new}\n")

    print("\nConfiguration saved to interface_config.txt")

if __name__ == "__main__":
    main()
