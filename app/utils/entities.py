from __future__ import annotations

# Expanded vendor list — covers major enterprise/ICS/cloud/network vendors
VENDORS = [
    # Network / Security
    "Fortinet", "Palo Alto", "Palo Alto Networks", "Cisco", "Juniper", "F5", "SonicWall",
    "Zyxel", "Sophos", "Barracuda", "Check Point", "Watchguard", "Netgear", "D-Link",
    "TP-Link", "Aruba", "Extreme Networks", "Pulse Secure", "Ivanti", "Citrix",
    # OS / Cloud
    "Microsoft", "Apple", "Google", "Linux", "Ubuntu", "Red Hat", "SUSE", "Debian",
    "VMware", "Broadcom", "Oracle", "IBM", "SAP", "Atlassian", "Confluence", "Jira",
    "Salesforce", "ServiceNow", "Adobe", "Zoom", "Slack",
    # ICS / OT
    "Schneider Electric", "Rockwell Automation", "Siemens", "ABB", "Honeywell",
    "GE", "Emerson", "Mitsubishi Electric", "Yokogawa", "Phoenix Contact",
    "Beckhoff", "Wago", "Moxa", "Advantech", "Delta Electronics", "Festo",
    # Dev / Open source
    "Apache", "Nginx", "OpenSSL", "curl", "libssl", "Spring", "Log4j",
    "WordPress", "Drupal", "Joomla", "PHP", "Python", "Node.js",
    # Other
    "SmarterTools", "GNU", "Veeam", "Progress", "MOVEit", "Ivanti",
    "PaperCut", "Zimbra", "OpenFire", "MikroTik", "Ubiquiti",
]

# Expanded product list
PRODUCT_HINTS = [
    "FortiGate", "FortiOS", "FortiManager", "FortiAnalyzer", "FortiProxy",
    "SmarterMail", "Endpoint Manager Mobile", "EPMM", "Ivanti Connect Secure",
    "Pulse Connect", "CODESYS", "Zigbee", "ArmorStart", "Office", "PLC",
    "Exchange", "SharePoint", "Active Directory", "Azure", "Windows", "Defender",
    "Chrome", "Firefox", "Safari", "Webkit",
    "vCenter", "ESXi", "Workstation", "Fusion",
    "AnyConnect", "ASA", "IOS XE", "NX-OS",
    "GlobalProtect", "PAN-OS",
    "NetScaler", "ADC", "Gateway",
    "MOVEit Transfer", "MOVEit Cloud",
    "OpenSSL", "Log4Shell", "Spring4Shell",
    "TeamViewer", "Solarwinds", "Kaseya",
    "BIG-IP", "TMOS",
    "Confluence", "Jira", "Bitbucket",
]

# Deduplicate and lowercase-index for fast matching
_VENDOR_MAP = {v.lower(): v for v in VENDORS}
_PRODUCT_MAP = {p.lower(): p for p in PRODUCT_HINTS}


def extract_vendor_product(title: str, text: str):
    blob = f"{title}\n{text}".lower()

    vendor = None
    for key, canonical in _VENDOR_MAP.items():
        if key in blob:
            vendor = canonical
            break

    product = None
    for key, canonical in _PRODUCT_MAP.items():
        if key in blob:
            product = canonical
            break

    return vendor, product
