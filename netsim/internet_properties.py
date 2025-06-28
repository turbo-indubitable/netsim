# netsim/utils/internet_properties.py

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
    props = json.loads(props_json)
    keys = list(props.keys())
    return [f"{src}_to_{dst}" for src in keys for dst in keys]


def choose_random_ip(ip_range: str) -> str:
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
    if source_type not in props:
        raise ValueError(f"Invalid source_type: {source_type}")
    if name not in props[source_type]:
        raise ValueError(f"Unknown {source_type} name: {name}")

    ip_range = random.choice(props[source_type][name]["ip_ranges"])
    return choose_random_ip(ip_range)

def choose_ip_pair(flow_type: str, props: dict = internet_properties) -> tuple[str, str]:
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