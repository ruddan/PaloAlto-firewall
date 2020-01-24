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

    vsys_xml = create_vsys_xml()
    policy_xml = create_policy_xml(
        args.source, args.user, args.dest, args.destport, args.protocol
    )
    vsys_url = create_url(vsys_xml)
    policy_url = create_url(policy_xml)
    api_data = api_call(vsys_url, policy_url)
    xml_parse(api_data, args.source, args.user, args.dest)


def create_vsys_xml():
    # Set vsys xml
    vsys_root = ET.Element("set")
    set_system = ET.SubElement(vsys_root, "system")
    set_setting = ET.SubElement(set_system, "setting")
    # <vsysX> X needs to be replaced with number of vsys, <vsys1>
    ET.SubElement(set_setting, "target-vsys").text = r"<vsysX>"

    ET.ElementTree(vsys_root)
    xmlstring = ET.tostring(vsys_root)

    return xmlstring


def create_policy_xml(sip, usr, dip, dport, protocol):
    # Create Security policy match xml
    policy_root = ET.Element("test")
    security_policy = ET.SubElement(policy_root, "security-policy-match")

    ET.SubElement(security_policy, "source").text = r"{}".format(sip)
    ET.SubElement(security_policy, "source-user").text = r"{}".format(usr)
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
    # Make the call
    requests.get(vsys_url)
    r_policy = requests.get(policy_url)
    api_data = r_policy.content

    return api_data


def xml_parse(api_data, sip, usr, dip):
    # Convert xml to dict and print
    ET.fromstring(api_data)
    xml_dict = xmltodict.parse(api_data)

    for k, v in xml_dict.items():
        print("\nUsername: {}".format(usr))
        print("Source IP: {}".format(sip))
        print("Destination IP: {}".format(dip))
        print("Rule name: {}".format(v["result"]["rules"]["entry"]["@name"]))
        print("Traffic flow: {}".format(v["result"]["rules"]["entry"]["action"]))


if __name__ == "__main__":
    main()
