# netsim/pattern_registry.py

from netsim.patterns.patterns import (
    TCPHandshakePattern,
    UDPDNSFragmentedPattern,
    ICMPUnreachablePattern,
    NTPPattern,
    SNMPPattern,
    GREPattern,
    IPSECISAKMPPattern,
    HTTPSWebBrowsePattern,
    DNSNormalPattern,
    QUICVideoPattern
)
from netsim.patterns.patterns import (FSMUDPSessionPattern, FSMTCPSessionPattern, FSMQUICSessionPattern,
                                      FSMGRESessionPattern, FSMIPsecSessionPattern, FSMBGPSessionPattern,
                                      FSMHTTPPattern, FSMHTTPSPattern, FSMSSHPattern)

PATTERN_CLASSES = [
    TCPHandshakePattern,
    UDPDNSFragmentedPattern,
    ICMPUnreachablePattern,
    NTPPattern,
    SNMPPattern,
    GREPattern,
    IPSECISAKMPPattern,
    HTTPSWebBrowsePattern,
    DNSNormalPattern,
    QUICVideoPattern,
    FSMTCPSessionPattern,
    FSMUDPSessionPattern,
    FSMQUICSessionPattern,
    FSMGRESessionPattern,
    FSMIPsecSessionPattern,
    FSMBGPSessionPattern,
    FSMHTTPPattern,
    FSMHTTPSPattern,
    FSMSSHPattern
]

PATTERN_REGISTRY = {
    cls.name: cls for cls in PATTERN_CLASSES
}