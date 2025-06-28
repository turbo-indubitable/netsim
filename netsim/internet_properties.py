# netsim/utils/internet_properties.py
"""
Internet Properties Module

This module provides functionality for working with realistic internet topology
and IP address allocation. It contains a model of the internet divided into
different categories (consumer ISPs, CDNs, and online services) with their
associated ASNs and IP ranges.

The module offers functions to:  
- Generate network flows between different internet entities
- Select random IP addresses from appropriate ranges
- Map ASNs to their associated IP ranges
- Create realistic network traffic patterns
"""

import ipaddress
import random
import functools
import json
from collections import defaultdict

internet_properties = {
    "consumer": {
        "Comcast": {
            "asn": ["AS7922"],
            "ip_ranges": [
                "73.0.0.0/8",
                "24.0.0.0/9"
            ]
        },
        "AT&T": {
            "asn": ["AS7018"],
            "ip_ranges": [
                "99.0.0.0/8",
                "76.0.0.0/8"
            ]
        },
        "Verizon": {
            "asn": ["AS701"],
            "ip_ranges": [
                "71.0.0.0/8",
                "72.0.0.0/8"
            ]
        },
        "Charter": {
            "asn": ["AS20115"],
            "ip_ranges": [
                "66.0.0.0/8"
            ]
        },
        "T-Mobile": {
            "asn": ["AS21928"],
            "ip_ranges": [
                "172.58.0.0/15",
                "172.56.0.0/14"
            ]
        }
    },
    "cdn": {
        "Cloudflare": {
            "asn": ["AS13335"],
            "ip_ranges": [
                "104.16.0.0/12",
                "172.64.0.0/13",
                "131.0.72.0/22"
            ]
        },
        "Akamai": {
            "asn": ["AS12222", "AS16625", "AS16702"],
            "ip_ranges": [
                "23.0.0.0/12",
                "23.32.0.0/11",
                "23.64.0.0/14"
            ]
        },
        "Fastly": {
            "asn": ["AS54113"],
            "ip_ranges": [
                "151.101.0.0/16",
                "199.232.0.0/16",
                "2a04:4e40::/32"
            ]
        },
        "Amazon CloudFront": {
            "asn": ["AS16509"],
            "ip_ranges": [
                "13.32.0.0/15",
                "13.35.0.0/16",
                "13.224.0.0/14"
            ]
        },
        "StackPath": {
            "asn": ["AS12989"],
            "ip_ranges": [
                "151.139.0.0/16",
                "151.139.128.0/17",
                "151.139.192.0/18"
            ]
        },
        "Sucuri": {
            "asn": ["AS30148"],
            "ip_ranges": [
                "192.124.249.0/24",
                "192.124.250.0/24",
                "192.124.251.0/24"
            ]
        },
        "Imperva": {
            "asn": ["AS19551"],
            "ip_ranges": [
                "107.154.0.0/16",
                "45.64.64.0/22",
                "45.64.68.0/22"
            ]
        }
    },
    "service": {
        "Google": {
            "asn": ["AS15169"],
            "ip_ranges": ["142.250.190.14"]
        },
        "Facebook": {
            "asn": ["AS32934"],
            "ip_ranges": ["157.240.22.35"]
        },
        "YouTube": {
            "asn": ["AS15169"],
            "ip_ranges": ["142.250.190.206"]
        },
        "Twitter": {
            "asn": ["AS13414"],
            "ip_ranges": ["104.244.42.1"]
        },
        "Amazon": {
            "asn": ["AS16509"],
            "ip_ranges": ["176.32.103.205"]
        },
        "Netflix": {
            "asn": ["AS2906"],
            "ip_ranges": ["52.89.124.203"]
        },
        "LinkedIn": {
            "asn": ["AS14413"],
            "ip_ranges": ["108.174.10.10"]
        },
        "Instagram": {
            "asn": ["AS32934"],
            "ip_ranges": ["157.240.22.174"]
        },
        "Reddit": {
            "asn": ["AS54113"],
            "ip_ranges": ["151.101.65.140"]
        },
        "Wikipedia": {
            "asn": ["AS14907"],
            "ip_ranges": ["208.80.154.224"]
        }
    }
}

@functools.lru_cache(maxsize=None)
def list_valid_flow_types(props_json: str = json.dumps(internet_properties)) -> list[str]:
    """
    Get a list of all valid flow types based on the internet properties configuration.

    This function generates all possible combinations of source and destination
    network types in the format 'source_to_destination' (e.g., 'consumer_to_cdn').
    Results are cached using LRU cache for performance.

    Args:
        props_json (str): JSON string representation of internet properties.
                          Defaults to the built-in internet_properties dictionary.

    Returns:
        list[str]: List of all valid flow type strings in the format 'source_to_destination'
    """
    props = json.loads(props_json)
    keys = list(props.keys())
    return [f"{src}_to_{dst}" for src in keys for dst in keys]


def choose_random_ip(ip_range: str) -> str:
    """
    Choose a random IP address from within the specified IP range.

    This function selects a random usable IP address from the given range,
    avoiding the network and broadcast addresses when possible.

    Args:
        ip_range (str): An IP network range in CIDR notation (e.g., '192.168.1.0/24')
                        or a single IP address.

    Returns:
        str: A randomly selected IP address from the range as a string
    """
    net = ipaddress.ip_network(ip_range, strict=False)
    first_ip = int(net.network_address)
    last_ip = int(net.broadcast_address)

    if last_ip - first_ip <= 1:
        # Not enough room for a usable random IP, just return the network address
        return str(net.network_address)
    else:
        rand_ip = random.randint(first_ip + 1, last_ip - 1)
        return str(ipaddress.ip_address(rand_ip))

def choose_internet_ip(source_type: str, name: str, props: dict = internet_properties) -> str:
    """
    Choose a random IP address from a specific internet entity's IP ranges.

    This function selects a random IP address from the IP ranges associated with
    a specific entity (e.g., 'Comcast' within 'consumer' type) in the internet
    properties configuration.

    Args:
        source_type (str): The type of network entity (e.g., 'consumer', 'cdn', 'service')
        name (str): The name of the specific entity within that type (e.g., 'Comcast', 'Cloudflare')
        props (dict): Internet properties dictionary. Defaults to the built-in internet_properties.

    Returns:
        str: A randomly selected IP address as a string

    Raises:
        ValueError: If the source_type or name is not found in the properties
    """
    if source_type not in props:
        raise ValueError(f"Invalid source_type: {source_type}")
    if name not in props[source_type]:
        raise ValueError(f"Unknown {source_type} name: {name}")

    ip_range = random.choice(props[source_type][name]["ip_ranges"])
    return choose_random_ip(ip_range)

def choose_ip_pair(flow_type: str, props: dict = internet_properties) -> tuple[str, str]:
    """
    Choose a pair of source and destination IP addresses based on a flow type.

    This function selects appropriate source and destination IP addresses based on
    the specified flow type (e.g., 'consumer_to_cdn'). It randomly selects entities
    from each category and then chooses random IPs from their ranges.

    Args:
        flow_type (str): The type of network flow in format 'source_to_destination'
                        (e.g., 'consumer_to_cdn', 'service_to_consumer')
        props (dict): Internet properties dictionary. Defaults to the built-in internet_properties.

    Returns:
        tuple[str, str]: A tuple containing (source_ip, destination_ip) as strings

    Raises:
        ValueError: If the flow_type format is invalid or contains unknown types
    """
    parts = flow_type.lower().split("_to_")
    if len(parts) != 2:
        raise ValueError(f"Invalid flow_type '{flow_type}', expected format 'source_to_target'")

    src_type, dst_type = parts
    if src_type not in props or dst_type not in props:
        raise ValueError(f"Unknown source or destination type: {src_type}, {dst_type}")

    src_name = random.choice(list(props[src_type].keys()))
    dst_name = random.choice(list(props[dst_type].keys()))
    src_ip = choose_internet_ip(src_type, src_name, props)
    dst_ip = choose_internet_ip(dst_type, dst_name, props)
    return src_ip, dst_ip

def build_asn_ip_map(props: dict = internet_properties) -> dict[int, list[str]]:
    """
    Build a mapping of ASN numbers to their associated IP ranges.

    This function processes the internet properties configuration and creates a
    dictionary that maps each Autonomous System Number (ASN) to a list of all
    IP ranges associated with that ASN across all entity types.

    Args:
        props (dict): Internet properties dictionary. Defaults to the built-in internet_properties.

    Returns:
        dict[int, list[str]]: A dictionary mapping ASN numbers (as integers) to lists of IP ranges
    """
    asn_ip_map = defaultdict(list)
    for group in props.values():
        for entry in group.values():
            ip_ranges = entry.get("ip_ranges", [])
            for asn_str in entry.get("asn", []):
                try:
                    asn = int(asn_str.replace("AS", ""))
                    asn_ip_map[asn].extend(ip_ranges)
                except ValueError:
                    continue
    return dict(asn_ip_map)