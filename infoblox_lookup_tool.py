#!/usr/bin/env python3
import csv
import getpass
import re
import ipaddress
import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def api_get(url, eid, password):
    response = requests.get(
        url,
        auth=HTTPBasicAuth(eid, password),
        verify=False,
        timeout=60,
    )

    if response.status_code not in [200, 201]:
        print('\n' + '=' * 80)
        print('API ERROR')
        print('=' * 80)
        print(f'URL: {url}')
        print(f'Status Code: {response.status_code}')
        print(f'Response:\n{response.text}')
        print('=' * 80)
        response.raise_for_status()

    return response.json()


def get_networks(gridmaster, eid, password, wapi_version):
    url = (
        f'https://{gridmaster}'
        f'/wapi/{wapi_version}/network?_max_results=10000'
    )
    return api_get(url, eid, password)


def search_ip(gridmaster, eid, password, wapi_version, ip):
    url = (
        f'https://{gridmaster}'
        f'/wapi/{wapi_version}/ipv4address'
        f'?ip_address={ip}'
        f'&_return_fields=ip_address,names,network,mac_address,status'
    )
    return api_get(url, eid, password)


def search_subnet(gridmaster, eid, password, wapi_version, search_value):
    networks = get_networks(gridmaster, eid, password, wapi_version)
    search_value = search_value.strip()
    matches = []

    if '*' in search_value:
        pattern = '^' + re.escape(search_value).replace(r'\*', '.*') + '$'
        regex = re.compile(pattern, re.IGNORECASE)
        for network in networks:
            network_cidr = network.get('network', '')
            if regex.match(network_cidr):
                network['_match_type'] = 'WILDCARD_MATCH'
                matches.append(network)
        return sorted(matches, key=lambda x: x.get('network', ''))

    try:
        search_ip_addr = ipaddress.ip_address(search_value)
        for network in networks:
            network_cidr = network.get('network', '')
            try:
                subnet = ipaddress.ip_network(network_cidr, strict=False)
                if search_ip_addr in subnet:
                    network['_match_type'] = 'IP_IN_SUBNET'
                    matches.append(network)
            except Exception:
                pass

        matches.sort(
            key=lambda x: int(x.get('network', '0.0.0.0/0').split('/')[-1]),
            reverse=True,
        )
        return matches
    except ValueError:
        pass

    for network in networks:
        network_cidr = network.get('network', '')
        if search_value == network_cidr:
            network['_match_type'] = 'EXACT_MATCH'
            matches.append(network)

    if matches:
        return matches

    for network in networks:
        network_cidr = network.get('network', '')
        if search_value.lower() in network_cidr.lower():
            network['_match_type'] = 'PARTIAL_MATCH'
            matches.append(network)

    return sorted(matches, key=lambda x: x.get('network', ''))


def display_networks(networks):
    if not networks:
        print('\nNo matching networks found.')
        return

    print('\n' + '=' * 140)
    print(f"{'Subnet':<22}{'Match Type':<18}{'Network View':<25}{'Comment':<60}")
    print('=' * 140)

    for network in networks:
        print(
            f"{network.get('network',''):<22}"
            f"{network.get('_match_type',''):<18}"
            f"{network.get('network_view',''):<25}"
            f"{network.get('comment','')[:60]:<60}"
        )


def display_ip_results(results):
    if not results:
        print('\nNo matching IP found.')
        return

    for item in results:
        print(item)


def export_networks_csv(networks):
    filename = 'infoblox_networks.csv'
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Subnet', 'Network View', 'Comment'])
        for network in networks:
            writer.writerow([
                network.get('network', ''),
                network.get('network_view', ''),
                network.get('comment', ''),
            ])
    print(f'CSV written: {filename}')


def main():
    print('\nInfoblox Lookup Tool')
    gridmaster = input('Grid Manager Hostname/IP: ').strip()
    wapi_version = input('WAPI Version [v2.13]: ').strip() or 'v2.13'
    eid = input('EID: ').strip()
    password = getpass.getpass('Password: ')

    while True:
        print('\n1 - List All Networks')
        print('2 - Search IP Address')
        print('3 - Search Subnet/IP/Wildcard')
        print('4 - Export All Networks to CSV')
        print('5 - Exit')

        choice = input('Select option: ').strip()

        if choice == '1':
            display_networks(get_networks(gridmaster, eid, password, wapi_version))
        elif choice == '2':
            ip = input('IP Address: ').strip()
            display_ip_results(search_ip(gridmaster, eid, password, wapi_version, ip))
        elif choice == '3':
            value = input('Enter Subnet/IP/Wildcard: ').strip()
            display_networks(search_subnet(gridmaster, eid, password, wapi_version, value))
        elif choice == '4':
            export_networks_csv(get_networks(gridmaster, eid, password, wapi_version))
        elif choice == '5':
            break


if __name__ == '__main__':
    main()
