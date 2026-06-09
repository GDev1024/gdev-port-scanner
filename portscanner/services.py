"""
Port-to-service database, banner probes, and version-detection patterns.
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Port → (short_name, description)
# ---------------------------------------------------------------------------
SERVICES: dict[int, tuple[str, str]] = {
    1:     ("tcpmux",         "TCP Port Service Multiplexer"),
    7:     ("echo",           "Echo"),
    9:     ("discard",        "Discard"),
    13:    ("daytime",        "Daytime"),
    17:    ("qotd",           "Quote of the Day"),
    19:    ("chargen",        "Character Generator"),
    20:    ("ftp-data",       "FTP Data Transfer"),
    21:    ("ftp",            "File Transfer Protocol"),
    22:    ("ssh",            "Secure Shell"),
    23:    ("telnet",         "Telnet"),
    25:    ("smtp",           "Simple Mail Transfer Protocol"),
    37:    ("time",           "Time Protocol"),
    42:    ("nameserver",     "Host Name Server"),
    43:    ("whois",          "WHOIS"),
    53:    ("dns",            "Domain Name System"),
    67:    ("dhcp",           "DHCP Server"),
    68:    ("dhcp",           "DHCP Client"),
    69:    ("tftp",           "Trivial File Transfer Protocol"),
    70:    ("gopher",         "Gopher"),
    79:    ("finger",         "Finger"),
    80:    ("http",           "HyperText Transfer Protocol"),
    88:    ("kerberos",       "Kerberos"),
    102:   ("iso-tsap",       "ISO-TSAP"),
    110:   ("pop3",           "Post Office Protocol v3"),
    111:   ("rpcbind",        "Remote Procedure Call"),
    113:   ("ident",          "Identification Protocol"),
    119:   ("nntp",           "Network News Transfer Protocol"),
    123:   ("ntp",            "Network Time Protocol"),
    135:   ("msrpc",          "Microsoft RPC"),
    137:   ("netbios-ns",     "NetBIOS Name Service"),
    138:   ("netbios-dgm",    "NetBIOS Datagram Service"),
    139:   ("netbios-ssn",    "NetBIOS Session Service"),
    143:   ("imap",           "Internet Message Access Protocol"),
    161:   ("snmp",           "Simple Network Management Protocol"),
    162:   ("snmptrap",       "SNMP Trap"),
    179:   ("bgp",            "Border Gateway Protocol"),
    194:   ("irc",            "Internet Relay Chat"),
    220:   ("imap3",          "IMAP v3"),
    389:   ("ldap",           "Lightweight Directory Access Protocol"),
    443:   ("https",          "HTTP Secure"),
    445:   ("smb",            "Server Message Block"),
    465:   ("smtps",          "SMTP over SSL"),
    500:   ("ike",            "Internet Key Exchange"),
    512:   ("rexec",          "Remote Execution"),
    513:   ("rlogin",         "Remote Login"),
    514:   ("syslog",         "Syslog / Remote Shell"),
    515:   ("printer",        "Line Printer Daemon"),
    520:   ("rip",            "Routing Information Protocol"),
    521:   ("ripng",          "RIPng"),
    587:   ("submission",     "Email Message Submission"),
    631:   ("ipp",            "Internet Printing Protocol"),
    636:   ("ldaps",          "LDAP over SSL"),
    873:   ("rsync",          "rsync"),
    993:   ("imaps",          "IMAP over SSL"),
    995:   ("pop3s",          "POP3 over SSL"),
    1080:  ("socks",          "SOCKS Proxy"),
    1194:  ("openvpn",        "OpenVPN"),
    1433:  ("mssql",          "Microsoft SQL Server"),
    1434:  ("mssql-monitor",  "MS SQL Monitor"),
    1521:  ("oracle",         "Oracle Database"),
    1723:  ("pptp",           "Point-to-Point Tunneling Protocol"),
    2049:  ("nfs",            "Network File System"),
    2181:  ("zookeeper",      "Apache ZooKeeper"),
    2375:  ("docker",         "Docker API (plaintext)"),
    2376:  ("docker-tls",     "Docker API (TLS)"),
    3000:  ("http-alt",       "HTTP Alternate / Grafana"),
    3128:  ("squid",          "Squid Proxy"),
    3306:  ("mysql",          "MySQL Database"),
    3389:  ("rdp",            "Remote Desktop Protocol"),
    3690:  ("svn",            "Subversion"),
    4444:  ("backdoor",       "Common backdoor / Metasploit"),
    4500:  ("ike-nat",        "IKE NAT-Traversal"),
    5000:  ("upnp",           "UPnP / Flask Dev"),
    5432:  ("postgresql",     "PostgreSQL"),
    5555:  ("adb",            "Android Debug Bridge"),
    5601:  ("kibana",         "Kibana"),
    5900:  ("vnc",            "Virtual Network Computing"),
    5985:  ("winrm",          "Windows Remote Management (HTTP)"),
    5986:  ("winrm-https",    "Windows Remote Management (HTTPS)"),
    6379:  ("redis",          "Redis"),
    6443:  ("kubernetes",     "Kubernetes API Server"),
    6667:  ("irc",            "Internet Relay Chat"),
    7001:  ("weblogic",       "Oracle WebLogic"),
    7002:  ("weblogic-ssl",   "Oracle WebLogic SSL"),
    8000:  ("http-alt",       "HTTP Alternate"),
    8008:  ("http-alt",       "HTTP Alternate"),
    8080:  ("http-proxy",     "HTTP Proxy"),
    8081:  ("http-alt",       "HTTP Alternate"),
    8443:  ("https-alt",      "HTTPS Alternate"),
    8888:  ("http-alt",       "HTTP Alternate / Jupyter"),
    9000:  ("php-fpm",        "PHP-FPM"),
    9090:  ("prometheus",     "Prometheus / Zeus Admin"),
    9200:  ("elasticsearch",  "Elasticsearch HTTP"),
    9300:  ("elasticsearch",  "Elasticsearch Transport"),
    10000: ("webmin",         "Webmin"),
    27017: ("mongodb",        "MongoDB"),
    27018: ("mongodb",        "MongoDB"),
    27019: ("mongodb",        "MongoDB Config Server"),
    50000: ("db2",            "IBM DB2"),
}

# ---------------------------------------------------------------------------
# Predefined port lists
# ---------------------------------------------------------------------------
TOP_100_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 113, 119, 123, 135, 137, 138, 139,
    143, 161, 179, 194, 389, 443, 445, 465, 500, 512, 513, 514, 515, 520, 587,
    631, 636, 873, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 2049, 2181,
    2375, 2376, 3000, 3128, 3306, 3389, 3690, 4444, 4500, 5000, 5432, 5555,
    5601, 5900, 5985, 5986, 6379, 6443, 6667, 7001, 7002, 8000, 8008, 8080,
    8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 27017, 27018, 27019, 50000,
    # fill to 100
    7, 9, 13, 17, 19, 37, 43, 69, 70, 79, 102, 220, 521, 1025, 5060,
    4899, 49152, 49153, 49154,
]
TOP_100_PORTS = sorted(set(TOP_100_PORTS))[:100]

TOP_1000_PORTS: list[int] = list(range(1, 1001))

# ---------------------------------------------------------------------------
# Service probes  — bytes to send after connecting (None = read immediately)
# ---------------------------------------------------------------------------
SERVICE_PROBES: dict[str, Optional[bytes]] = {
    "ftp":        None,                          # server sends banner first
    "ssh":        None,                          # server sends version first
    "telnet":     None,
    "smtp":       b"EHLO portscanner\r\n",
    "pop3":       None,
    "imap":       b"A001 CAPABILITY\r\n",
    "http":       b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "https":      b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "http-proxy": b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "http-alt":   b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "https-alt":  b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "redis":      b"*1\r\n$4\r\nPING\r\n",
    "mysql":      None,                          # server sends greeting
    "vnc":        None,                          # server sends protocol version
    "rdp":        None,
    "smb":        None,
    "submission": b"EHLO portscanner\r\n",
    "smtps":      b"EHLO portscanner\r\n",
}

# Ports that use TLS/SSL at connect time
SSL_PORTS: frozenset[int] = frozenset([
    443, 465, 636, 993, 995, 5986, 8443, 7002,
])

# ---------------------------------------------------------------------------
# Version-detection patterns
# Each entry: (compiled_regex, service_label, version_template)
# In version_template, {1}, {2} … are substituted with regex groups.
# ---------------------------------------------------------------------------
VERSION_PATTERNS: list[tuple] = [
    # SSH
    (re.compile(r'SSH-[\d.]+-OpenSSH[_\s]+([\d.p]+)', re.I),  "SSH",   "OpenSSH {1}"),
    (re.compile(r'SSH-[\d.]+-dropbear[_\s]+([\d.]+)',  re.I),  "SSH",   "Dropbear SSH {1}"),
    (re.compile(r'SSH-([\d.]+)-(.+?)[\r\n]'),                   "SSH",   "{2} (proto {1})"),

    # HTTP servers
    (re.compile(r'Server:\s*Apache/([\d.]+)',           re.I),  "HTTP",  "Apache httpd {1}"),
    (re.compile(r'Server:\s*nginx/([\d.]+)',            re.I),  "HTTP",  "nginx {1}"),
    (re.compile(r'Server:\s*Microsoft-IIS/([\d.]+)',    re.I),  "HTTP",  "Microsoft IIS {1}"),
    (re.compile(r'Server:\s*lighttpd/([\d.]+)',         re.I),  "HTTP",  "lighttpd {1}"),
    (re.compile(r'Server:\s*Jetty\(([\d.]+)\)',         re.I),  "HTTP",  "Jetty {1}"),
    (re.compile(r'Server:\s*openresty/([\d.]+)',        re.I),  "HTTP",  "OpenResty {1}"),
    (re.compile(r'Server:\s*Caddy',                    re.I),  "HTTP",  "Caddy"),
    (re.compile(r'X-Powered-By:\s*PHP/([\d.]+)',        re.I),  "HTTP",  "PHP {1}"),

    # FTP
    (re.compile(r'vsftpd\s+([\d.]+)',                  re.I),  "FTP",   "vsftpd {1}"),
    (re.compile(r'ProFTPD\s+([\d.]+)',                  re.I),  "FTP",   "ProFTPD {1}"),
    (re.compile(r'FileZilla Server\s+([\d.]+)',         re.I),  "FTP",   "FileZilla Server {1}"),
    (re.compile(r'Pure-FTPd',                          re.I),  "FTP",   "Pure-FTPd"),
    (re.compile(r'Microsoft FTP Service',              re.I),  "FTP",   "Microsoft FTP"),

    # Mail
    (re.compile(r'Postfix',                            re.I),  "SMTP",  "Postfix"),
    (re.compile(r'Sendmail\s+([\d.]+)',                 re.I),  "SMTP",  "Sendmail {1}"),
    (re.compile(r'Exim\s+([\d.]+)',                    re.I),  "SMTP",  "Exim {1}"),
    (re.compile(r'Microsoft ESMTP',                    re.I),  "SMTP",  "Microsoft Exchange"),
    (re.compile(r'Dovecot',                            re.I),  "IMAP",  "Dovecot"),

    # Databases
    (re.compile(r'\+PONG',                             re.I),  "Redis", "Redis"),
    (re.compile(r'redis_version:([\d.]+)',              re.I),  "Redis", "Redis {1}"),
    (re.compile(r'([\d.]+)-MariaDB'),                           "MySQL", "MariaDB {1}"),
    (re.compile(r'MySQL\s*([\d.]+)',                   re.I),  "MySQL", "MySQL {1}"),

    # VNC
    (re.compile(r'RFB\s+([\d.]+)',                     re.I),  "VNC",   "VNC (RFB {1})"),

    # Generic
    (re.compile(r'MongoDB',                            re.I),  "MongoDB", "MongoDB"),
    (re.compile(r'Elasticsearch',                      re.I),  "Elasticsearch", "Elasticsearch"),
]


def get_service_name(port: int) -> str:
    """Return the short service name for a port, or empty string."""
    entry = SERVICES.get(port)
    return entry[0] if entry else ""


def get_probe(service: str) -> Optional[bytes]:
    """Return the probe bytes for a service name (may be None = read-first)."""
    return SERVICE_PROBES.get(service)


def detect_version(banner: str) -> tuple[str, str]:
    """
    Apply version-detection patterns to a banner string.
    Returns (service_label, version_string).  Both may be empty.
    """
    for pattern, service, version_fmt in VERSION_PATTERNS:
        m = pattern.search(banner)
        if m:
            version = version_fmt
            for i, grp in enumerate(m.groups(), 1):
                version = version.replace(f"{{{i}}}", grp or "")
            return service, version.strip()
    return "", ""
