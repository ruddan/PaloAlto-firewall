#!/usr/bin/python3

import requests
from ipaddress import ip_address
import argparse
import xml.etree.ElementTree as ET
import xmltodict
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description="Check if traffic is allowed")
    parser.add_argument(
        "--user", help="username",
    )
    parser.add_argument(
        "--source-ip",
        dest="source",
        type=ip_address,
        required=True,
        help="source IP-address",
    )
    parser.add_argument(
        "--dest-ip",
        dest="dest",
        type=ip_address,
        required=True,
        help="destination IP-address",
    )
    parser.add_argument(
        "--dest-port",
        type=int,
        dest="destport",
        required=True,
        help="destination port",
    )
    parser.add_argument(
        "--protocol",
        type=int,
        required=True,
        help="protocol number(1-255): tcp 6, udp 17, ICMP 1",
    )

    args = parser.parse_args()
    get_matched_policy(args.source, args.user, args.dest, args.destport, args.protocol)


def get_matched_policy(sip, username, dip, dport, protocol):
    # Create xml
    vsys_xml = create_vsys_xml()
    policy_xml = create_policy_xml(sip, username, dip, dport, protocol)
    # Create URL
    vsys_url = create_url(vsys_xml)
    policy_url = create_url(policy_xml)
    # API call
    matched_rules = api_call(vsys_url, policy_url)
    # Parse API response
    result = parse_xml(matched_rules)
    # Print
    print_result(result, sip, username, dip)


def create_vsys_xml():
    # Set vsys xml
    vsys_root = ET.Element("set")
    set_system = ET.SubElement(vsys_root, "system")
    set_setting = ET.SubElement(set_system, "setting")
    # vsysX X needs to be replaced with vsys number, vsys1
    ET.SubElement(set_setting, "target-vsys").text = r"vsysX"

    ET.ElementTree(vsys_root)
    xmlstring = ET.tostring(vsys_root)
    return xmlstring


def create_policy_xml(sip, usr, dip, dport, protocol):
    # Create Security policy match xml
    policy_root = ET.Element("test")
    security_policy = ET.SubElement(policy_root, "security-policy-match")

    if usr is not None:
        ET.SubElement(security_policy, "source-user").text = r"{}".format(usr)

    ET.SubElement(security_policy, "source").text = r"{}".format(sip)
    ET.SubElement(security_policy, "destination").text = r"{}".format(dip)
    ET.SubElement(security_policy, "destination-port").text = r"{}".format(dport)
    ET.SubElement(security_policy, "protocol").text = r"{}".format(protocol)

    ET.ElementTree(policy_root)
    xmlstring = ET.tostring(policy_root)

    return xmlstring


def create_url(xml):
    # API Key needs to be created via Palo Alto GUI - Recommended to create a new API-user with read only access
    api_key = "<token>"
    schema = "https"
    hostname = "firewall.com"
    path = "/api/"

    # Create vsys and test security policy url
    query_string = urllib.parse.urlencode({"type": "op", "cmd": xml, "key": api_key})
    return urllib.parse.urlunparse((schema, hostname, path, None, query_string, None))


def api_call(vsys_url, policy_url):
    # Make the call, you need to add "verify=False" to requests if you dont have proper certificate
    requests.get(vsys_url)
    r_policy = requests.get(policy_url)
    api_data = r_policy.content

    return api_data


def parse_xml(matched_rules_xml):
    # Convert xml to dict, iterate over dict and append results
    ET.fromstring(matched_rules_xml)
    matched_rules = xmltodict.parse(matched_rules_xml)

    rule_one = next(iter(matched_rules))  # Get first key
    rules = matched_rules[rule_one]  # Get the data for the key

    try:
        name = rules["result"]["rules"]["entry"]["@name"]
        action = rules["result"]["rules"]["entry"]["action"]

        result = {"name": name, "action": action, "error": None}
    except KeyError:
        result = {"error": rules["msg"]["line"]}
    return result


def print_result(result, sip, usr, dip):
    if result["error"] is not None:
        print(result["error"])
        return

    if usr is not None:
        print(f"\nUsername: {usr}")
    print(f"Source IP: {sip}")
    print(f"Destination IP: {dip}")
    print(f"Rule name: {result['name']}")
    print(f"Traffic flow: {result['action']}\n")


if __name__ == "__main__":
    main()
