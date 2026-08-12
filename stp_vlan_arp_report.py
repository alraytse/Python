#!/usr/bin/env python3
import getpass
import csv
import re
import ipaddress
from datetime import datetime
from netmiko import ConnectHandler

CSV_FILE = f"stp_vlan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"


def parse_vlans(output):
    vlans=[]
    for line in output.splitlines():
        m=re.match(r'^(\d+)\s+([^\s]+)', line.strip())
        if m:
            vlans.append({'vlan':m.group(1),'name':m.group(2)})
    return vlans


def check_root(connection,vlan):
    try:
        return 'This bridge is the root' in connection.send_command(f'show spanning-tree vlan {vlan}',read_timeout=30)
    except Exception:
        return False


def get_svi_info(connection,vlan):
    try:
        output=connection.send_command(f'show run interface vlan {vlan}',read_timeout=30)
        desc=''; ip=''
        for line in output.splitlines():
            line=line.strip()
            if line.startswith('description '):
                desc=line.replace('description ','')
            elif line.startswith('ip address '):
                ip=line.replace('ip address ','')
        return desc,ip
    except Exception:
        return '',''


def get_dynamic_mac_count(connection,vlan):
    try:
        output=connection.send_command(f'show mac address-table vlan {vlan}',read_timeout=60)
        return sum(1 for l in output.splitlines() if 'dynamic' in l.lower())
    except Exception:
        return 0


def get_arp_count(connection,vlan):
    for cmd in [f'show ip arp vlan {vlan}',f'show arp vlan {vlan}']:
        try:
            output=connection.send_command(cmd,read_timeout=60)
            return sum(1 for l in output.splitlines() if re.match(r'^\d+\.\d+\.\d+\.\d+',l.strip()))
        except Exception:
            pass
    return 0


def calculate_vlan_utilization(svi_ip,arp_count):
    try:
        if not svi_ip or '/' not in svi_ip:
            return 0
        network=ipaddress.ip_interface(svi_ip.split()[0]).network
        usable=max(network.num_addresses-2,1)
        return round((arp_count/usable)*100,2)
    except Exception:
        return 0


def get_hostname(connection):
    return connection.find_prompt().replace('#','').replace('>','').strip()


def process_switch(device):
    results=[]
    conn=ConnectHandler(**device)
    hostname=get_hostname(conn)
    vlans=parse_vlans(conn.send_command('show vlan brief',read_timeout=60))

    for v in vlans:
        vlan=v['vlan']
        root=check_root(conn,vlan)
        desc,ip=get_svi_info(conn,vlan)
        macs=get_dynamic_mac_count(conn,vlan)
        arps=get_arp_count(conn,vlan)
        util=calculate_vlan_utilization(ip,arps)
        decom=(macs==0 and arps==0 and not root)

        results.append({
            'Device':hostname,
            'VLAN':vlan,
            'VLAN_Name':v['name'],
            'SVI_IP':ip,
            'SVI_Description':desc,
            'Dynamic_MACs':macs,
            'ARP_Count':arps,
            'VLAN_Utilization_Pct':util,
            'Root_Bridge':'YES' if root else 'NO',
            'Decom_Candidate':'YES' if decom else 'NO',
            'Decom_Reason':'No Dynamic MACs, No ARP Entries, Not STP Root' if decom else ''
        })

    conn.disconnect()
    return results


def write_csv(results):
    fields=['Run','Timestamp','Device','VLAN','VLAN_Name','SVI_IP','SVI_Description','Dynamic_MACs','ARP_Count','VLAN_Utilization_Pct','Root_Bridge','Decom_Candidate','Decom_Reason']
    with open(CSV_FILE,'w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields)
        w.writeheader(); w.writerows(results)


def main():
    hosts=input('Enter switch hostnames/IPs (comma separated): ').strip()
    host_list=[h.strip() for h in hosts.split(',') if h.strip()]
    platform=input('Platform (nxos/iosxe): ').strip().lower()
    device_type='cisco_ios' if platform=='iosxe' else 'cisco_nxos'
    username=input('Username: ')
    password=getpass.getpass('Password: ')
    run_count=int(input('How many times would you like to run the audit? '))

    all_results=[]
    for run in range(1,run_count+1):
        ts=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f'Run {run}/{run_count} - {ts}')
        for host in host_list:
            device={'device_type':device_type,'host':host,'username':username,'password':password,'fast_cli':False}
            try:
                rows=process_switch(device)
                for r in rows:
                    r['Run']=run
                    r['Timestamp']=ts
                all_results.extend(rows)
            except Exception as e:
                print(f'{host}: {e}')

    write_csv(all_results)
    print(f'CSV report saved to: {CSV_FILE}')

if __name__ == '__main__':
    main()
