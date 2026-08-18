#!/usr/bin/env python3
import re
import csv
import socket
from getpass import getpass
from netmiko import ConnectHandler

OUTPUT_CSV = "inventory_report.csv"

VENDOR_KEYWORDS = {
    "VERIZON": "Verizon",
    "ATT": "AT&T",
    "AT&T": "AT&T",
    "LUMEN": "Lumen",
    "CENTURYLINK": "CenturyLink",
    "COGENT": "Cogent",
    "COMCAST": "Comcast",
    "CHARTER": "Charter",
    "ZAYO": "Zayo",
    "WINDSTREAM": "Windstream"
}

KEYWORD_DEFINITIONS = {
    "FW": "Firewall Connection",
    "FIREWALL": "Firewall Connection",
    "ISP": "Internet Service Provider Connection",
    "INTERNET": "Internet Circuit",
    "MPLS": "MPLS WAN Circuit",
    "VPN": "VPN Connection",
    "WAN": "Wide Area Network Connection",
    "VERIZON": "Verizon Carrier Circuit",
    "ATT": "AT&T Carrier Circuit",
    "LUMEN": "Lumen Carrier Circuit",
    "CENTURYLINK": "CenturyLink Carrier Circuit",
    "COGENT": "Cogent Carrier Circuit",
    "COMCAST": "Comcast Carrier Circuit",
    "CHARTER": "Charter Carrier Circuit",
    "ZAYO": "Zayo Carrier Circuit",
    "WINDSTREAM": "Windstream Carrier Circuit",
    "DMZ": "Demilitarized Zone",
    "PCI": "PCI Network",
    "B2B": "Business-to-Business Network",
    "USON": "US Oncology Network"
}

TYPE_KEYWORDS = {
    "FW": "Firewall",
    "FIREWALL": "Firewall",
    "ISP": "Internet",
    "INTERNET": "Internet",
    "MPLS": "MPLS",
    "VPN": "VPN",
    "WAN": "WAN"
}


def resolve_ip(hostname):
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return hostname


def detect_vendor(description):
    d = description.upper()
    for k, v in VENDOR_KEYWORDS.items():
        if k in d:
            return v
    return 'Unknown'


def detect_circuit_type(description):
    d = description.upper()
    found = [v for k, v in TYPE_KEYWORDS.items() if k in d]
    return ','.join(sorted(set(found))) if found else 'Unknown'


def matched_keywords(description):
    d = description.upper()
    matches = [k for k in KEYWORD_DEFINITIONS if k in d]
    return ','.join(sorted(set(matches)))


def matched_keyword_definitions(description):
    d = description.upper()
    defs = [v for k, v in KEYWORD_DEFINITIONS.items() if k in d]
    return '; '.join(sorted(set(defs)))


def find_attached_device(description):
    m = re.findall(r'(DDC1-[A-Za-z0-9\-]+|BUMSH\d+)', description, re.I)
    return m[0] if m else ''


def extract_circuit_id(text):
    patterns = [
        r'CID[:=\s]+([A-Za-z0-9\-_/\.]+)',
        r'CKT[:=\s]+([A-Za-z0-9\-_/\.]+)',
        r'CIRCUIT[:=\s]+([A-Za-z0-9\-_/\.]+)',
        r'VCID[:=\s]+([A-Za-z0-9\-_/\.]+)',
        r'\bVZ[0-9]{6,}\b',
        r'\bATT[0-9]{6,}\b',
        r'\bCTL[0-9]{6,}\b',
        r'\bZAYO[0-9]{6,}\b',
        r'\b[A-Z]{2,5}[0-9]{6,}\b'
    ]

    for pattern in patterns:
        m = re.search(pattern, text, re.I)
        if m:
            return m.group(1) if m.groups() else m.group(0)

    return ''


def build_notes(status, vendor, circuit_id):
    notes = []

    if status.lower() not in ['connected', 'up']:
        notes.append('Interface Down')

    if vendor == 'Unknown':
        notes.append('Vendor Unknown')

    if circuit_id:
        notes.append(f'Circuit ID Found: {circuit_id}')
    else:
        notes.append('Circuit ID Missing')

    return '; '.join(notes)


def parse_interface_config(cfg):
    mode = ''
    native = ''
    allowed = ''

    m = re.search(r'switchport mode\s+(\S+)', cfg, re.I)
    if m:
        mode = m.group(1)

    m = re.search(r'switchport trunk native vlan\s+(\d+)', cfg, re.I)
    if m:
        native = m.group(1)

    m = re.search(r'switchport trunk allowed vlan\s+([0-9,\-]+)', cfg, re.I)
    if m:
        allowed = m.group(1)

    return mode, native, allowed


def connect_device(host, username, password):
    return ConnectHandler(device_type='cisco_nxos', host=host, username=username, password=password, fast_cli=False)


def main():
    devices = input('Enter device names (comma separated): ').strip()
    username = input('Username: ').strip()
    password = getpass('Password: ')

    report = []

    for host in [x.strip() for x in devices.split(',') if x.strip()]:
        try:
            print(f'Connecting to {host} ...')
            conn = connect_device(host, username, password)
            conn.disable_paging()

            output = conn.send_command('show interface status', read_timeout=120)
            mgmt_ip = resolve_ip(host)

            for line in output.splitlines():
                if not re.match(r'^(Eth|Po|mgmt)', line.strip()):
                    continue

                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) < 3:
                    continue

                interface = parts[0]
                description = parts[1] if len(parts) > 4 else ''
                status = parts[2] if len(parts) > 4 else parts[1]
                vlan = parts[3] if len(parts) > 4 else ''

                try:
                    cfg = conn.send_command(f'show running-config interface {interface}')
                except Exception:
                    cfg = ''

                mode, native, allowed = parse_interface_config(cfg)

                circuit_id = extract_circuit_id(description)
                if not circuit_id:
                    circuit_id = extract_circuit_id(cfg)

                vendor = detect_vendor(description)

                report.append({
                    'Device': host,
                    'Management IP': mgmt_ip,
                    'Interface': interface,
                    'Interface Status': status,
                    'Admin Status': status,
                    'Operational Status': status,
                    'VLAN': vlan,
                    'Mode': mode,
                    'Native VLAN': native,
                    'Allowed VLANs': allowed,
                    'Circuit Vendor': vendor,
                    'Circuit IDs': circuit_id,
                    'Circuit Type': detect_circuit_type(description),
                    'Circuit Directly Attached': find_attached_device(description),
                    'Matched Keywords': matched_keywords(description),
                    'Matched Keyword Definitions': matched_keyword_definitions(description),
                    'Description': description,
                    'Notes': build_notes(status, vendor, circuit_id)
                })

            conn.disconnect()

        except Exception as e:
            print(f'{host}: {e}')

    fields = ['Device','Management IP','Interface','Interface Status','Admin Status','Operational Status','VLAN','Mode','Native VLAN','Allowed VLANs','Circuit Vendor','Circuit IDs','Circuit Type','Circuit Directly Attached','Matched Keywords','Matched Keyword Definitions','Description','Notes']

    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(report)

    print(f'CSV written to {OUTPUT_CSV}')
    print(f'Interfaces processed: {len(report)}')


if __name__ == '__main__':
    main()
