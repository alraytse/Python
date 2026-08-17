#!/usr/bin/env python3
import csv
import getpass
import ipaddress
import re
from datetime import datetime
from netmiko import ConnectHandler

OUTPUT_FILE = f"decom_candidates_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

def get_subnets():
    print("\n=== Subnet Range Input ===")
    start_subnet = input("Starting Subnet: ").strip()
    end_subnet = input("Ending Subnet: ").strip()
    start_net = ipaddress.ip_network(start_subnet, strict=False)
    end_net = ipaddress.ip_network(end_subnet, strict=False)
    if start_net.prefixlen != end_net.prefixlen:
        raise ValueError('Starting and Ending subnets must use same mask')
    subnets=[]
    current=int(start_net.network_address)
    ending=int(end_net.network_address)
    increment=start_net.num_addresses
    while current <= ending:
        subnets.append(str(ipaddress.ip_network((ipaddress.ip_address(current), start_net.prefixlen), strict=False)))
        current += increment
    return subnets

def get_switches():
    value=input('Switches (comma separated): ').strip()
    return [x.strip() for x in value.split(',') if x.strip()]

def subnet_details(subnet):
    net=ipaddress.ip_network(subnet, strict=False)
    hosts=list(net.hosts())
    return {
        'Network': str(net.network_address),
        'Netmask': str(net.netmask),
        'Prefix': net.prefixlen,
        'FirstUsable': str(hosts[0]) if hosts else str(net.network_address),
        'LastUsable': str(hosts[-1]) if hosts else str(net.broadcast_address),
        'UsableIPs': len(hosts)
    }

def get_route(conn, subnet):
    for cmd in [f'show ip route {subnet}', f'show route {subnet}']:
        try:
            out=conn.send_command(cmd)
            if out:
                return out
        except Exception:
            pass
    return ''

def classify_route(route):
    route=route.lower()
    if 'null0' in route: return 'Null0'
    if 'vlan' in route: return 'Connected'
    if 'static' in route: return 'Static'
    if 'bgp' in route: return 'BGP'
    return 'Unknown'

def extract_vlan(route):
    m=re.search(r'vlan(\d+)', route, re.I)
    return m.group(1) if m else ''

def extract_interface(route):
    for p in [r'Vlan\d+', r'Ethernet\S+', r'Port-channel\S+', r'Loopback\d+']:
        m=re.search(p, route, re.I)
        if m: return m.group(0)
    return ''

def get_arp_count(conn, vlan):
    if not vlan: return 0
    try:
        output=conn.send_command(f'show ip arp vlan {vlan}')
    except Exception:
        return 0
    count=0
    for line in output.splitlines():
        if 'incomplete' in line.lower():
            continue
        if re.search(r'\d+\.\d+\.\d+\.\d+', line):
            count += 1
    return count

def get_bgp_status(conn, subnet):
    for cmd in [f'show ip bgp {subnet}', f'show bgp ipv4 unicast {subnet}']:
        try:
            out=conn.send_command(cmd)
            if out and 'not in table' not in out.lower():
                return True
        except Exception:
            pass
    return False

def calculate_score(route_type, arp_count, bgp):
    score=100
    if route_type != 'Null0': score -= 30
    if arp_count > 0: score -= 40
    if bgp: score -= 30
    return max(score,0)

def classify_candidate(route_type, arp_count, bgp):
    if route_type=='Null0' and arp_count==0 and not bgp:
        return 'HIGH_CONFIDENCE_DECOM'
    if arp_count==0:
        return 'REVIEW_REQUIRED'
    return 'ACTIVE'

def main():
    subnets=get_subnets()
    switches=get_switches()
    username=input('Username: ').strip()
    password=getpass.getpass('Password: ')
    results=[]
    for switch in switches:
        device={'device_type':'cisco_nxos','host':switch,'username':username,'password':password}
        try:
            conn=ConnectHandler(**device)
        except Exception as e:
            print(f'Failed {switch}: {e}')
            continue
        for subnet in subnets:
            route=get_route(conn, subnet)
            route_type=classify_route(route)
            vlan=extract_vlan(route)
            arp=get_arp_count(conn, vlan)
            bgp=get_bgp_status(conn, subnet)
            info=subnet_details(subnet)
            results.append({
                'Subnet': subnet,
                'Network': info['Network'],
                'Prefix': info['Prefix'],
                'FirstUsable': info['FirstUsable'],
                'LastUsable': info['LastUsable'],
                'UsableIPs': info['UsableIPs'],
                'Switch': switch,
                'Interface': extract_interface(route),
                'VLAN': vlan,
                'RouteType': route_type,
                'ARP_Count': arp,
                'BGP_Advertised': bgp,
                'Score': calculate_score(route_type, arp, bgp),
                'Status': classify_candidate(route_type, arp, bgp)
            })
        conn.disconnect()
    if results:
        with open(OUTPUT_FILE,'w',newline='') as f:
            writer=csv.DictWriter(f, fieldnames=list(results[0].keys()))
            writer.writeheader(); writer.writerows(results)
        print(f'Report written to {OUTPUT_FILE}')

if __name__ == '__main__':
    main()
