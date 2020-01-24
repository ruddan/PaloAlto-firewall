## Security policy match

Match security policy via API call to PaloAlto firewall API. Script takes source ip, destination ip, destination port, protocol and user as input.

Function "create_vsys_xml" is only needed when using a multi-vsys environment.

## Usage

palo_test_security_policy.py --user username --source-ip 10.10.10.10 --dest-ip 11.11.11.11 --dest-port 22 --protocol 6
