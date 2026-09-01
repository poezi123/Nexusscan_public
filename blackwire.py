#!/usr/bin/env python3
import socket, threading, argparse, time, sys, re, json, ssl, os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from colorama import init, Fore, Style, Back
init(autoreset=True)

VERSION = "3.1"
APP_NAME = "BlackWire"

CVE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_db.json")

_cve_db = None
def show_help():
    """Display help information without spawning a subprocess."""
    import argparse
    parser = argparse.ArgumentParser(description=f'{APP_NAME} v{VERSION}')
    parser.add_argument('command', nargs='?', choices=['scan', 'web'], help='Command')
    parser.add_argument('-t','--target',type=str,help='Target IP or hostname')
    parser.add_argument('-p','--ports',type=str,help='Port specification')
    parser.add_argument('--top-ports',type=int,help='Only scan top N ports')
    parser.add_argument('-n','--threads',type=int,default=50,help='Threads')
    parser.add_argument('--timeout',type=float,default=2.0,help='Timeout')
    parser.add_argument('--no-banner',action='store_true',help='Disable banner grabbing')
    parser.add_argument('--no-color',action='store_true',help='Disable colors')
    parser.add_argument('-v','--verbose',action='store_true',help='Verbose output')
    parser.add_argument('--json',type=str,metavar='FILE',help='Export as JSON')
    parser.add_argument('--rate-limit',type=int,default=0,help='Rate limit')
    parser.print_help()
def load_cve_db():
    global _cve_db
    if _cve_db is not None:
        return _cve_db
    try:
        with open(CVE_DB_PATH, 'r', encoding='utf-8') as f:
            _cve_db = json.load(f)
        return _cve_db
    except:
        return {}

def lookup_cves(service_name, version):
    db = load_cve_db()
    if not db or not version:
        return []
    results = []
    sl = service_name.lower()
    sm = {
        "apache":["apache","httpd"],
        "nginx":["nginx"],
        "mysql":["mysql"],
        "php":["php"],
        "mssql":["microsoft sql server","mssql","sql server"],
        "ftp":["vsftpd","proftpd","ftp"],
        "smb":["samba","smb"],
        "tomcat":["tomcat"],
        "wordpress":["wordpress"],
        "postgresql":["postgresql","postgres"],
        "redis":["redis"],
        "ssh":["openssh","ssh"]
    }
    matched = None
    for cat, kws in sm.items():
        if any(k in sl for k in kws):
            matched = cat
            break
    if not matched or matched not in db:
        return []
    for sname, vers in db[matched].items():
        for ver, cves in vers.items():
            if version.startswith(ver) or ver.startswith(version):
                results.extend(cves)
    return list(set(results))

COMMON_PORTS = [
    21,22,23,25,53,80,81,110,111,135,
    139,143,161,179,389,443,445,465,514,554,
    587,631,636,646,873,990,993,995,1080,1194,
    1352,1433,1434,1521,1723,2049,2082,2083,2181,2375,
    2376,3128,3306,3389,3690,4333,4444,4786,4848,5000,
    5060,5222,5353,5432,5555,5601,5672,5900,5984,5985,
    5986,6379,6443,6580,7001,7077,7474,8000,8001,8008,
    8009,8010,8020,8042,8060,8069,8070,8080,8081,8082,
    8083,8088,8089,8090,8091,8092,8100,8181,8200,8222,
    8243,8280,8300,8400,8443,8484,8500,8530,8531,8806
]

COMMON_SUBDOMAINS = [
    "www","mail","ftp","admin","blog","webmail","vpn","ssh",
    "remote","smtp","pop3","imap","secure","portal","cpanel",
    "whm","webdisk","mysql","phpmyadmin","test","dev","api",
    "beta","stage","demo","backup","dns","ns1","ns2","mx",
    "srv","mail2","web","app","m","mobile","shop","store",
    "cloud","wiki","forum","support","help","status","cdn",
    "static","assets","img","images","download","upload",
    "git","jenkins","jira","confluence","sonar","nexus",
    "grafana","prometheus","kibana","elastic","kafka",
    "db","database","redis","mongo","postgres","sql",
    "proxy","gateway","auth","login","sso","account",
    "owa","exchange","autodiscover","lync","sfb",
    "intranet","erp","crm","hr","finance","ticket",
    "service","server","node1","node2","cluster",
    "docker","k8s","kubernetes","swarm","traefik",
    "monitor","monitoring","nagios","zabbix","icinga",
    "analytics","logs","log","report","reports","dashboard",
    "panel","manager","management","adminer","phpadmin",
    "wordpress","wp-admin","wp-login","xmlrpc",
    "lms","moodle","chamilo","ilias","studip",
    "webmin","usermin","cacti","observium","librenms",
    "pfsense","opnsense","router","switch","nas","san",
    "camera","cam","video","stream","streaming","live",
    "chat","webchat","conference","meet","team",
    "calendar","contacts","tasks","notes","sync",
    "api-dev","api-test","api-v1","api-v2","api-staging",
    "docs","developer","developers","statuspage",
    "s3","bucket","storage","files","file",
    "gitlab","bitbucket","gitea","gogs",
    "sonarqube","harbor","registry",
    "matrix","element","synapse","riot",
    "nextcloud","owncloud","seafile",
    "piwik","matomo","statistics","stats",
    "new","old","stage","staging","prod","production",
    "lb","loadbalancer","balancer","ha",
    "customer","clients","partner","vendors",
    "downloads","faq","knowledgebase","kb"
]

PORT_SERVICES = {
    20:"FTP-Daten",21:"FTP",22:"SSH",23:"Telnet",
    25:"SMTP",53:"DNS",80:"HTTP",81:"HTTP-Alt",
    110:"POP3",111:"RPC",135:"MSRPC",139:"NetBIOS",
    143:"IMAP",161:"SNMP",179:"BGP",389:"LDAP",
    443:"HTTPS",445:"SMB",465:"SMTPS",514:"Syslog",
    554:"RTSP",587:"SMTP-Submission",631:"IPP",
    636:"LDAPS",646:"LDP",873:"Rsync",990:"FTPS",
    993:"IMAPS",995:"POP3S",1080:"SOCKS-Proxy",
    1194:"OpenVPN",1352:"Lotus-Notes",1433:"MSSQL",
    1434:"MSSQL-Monitor",1521:"Oracle-DB",1723:"PPTP",
    2049:"NFS",2082:"cPanel",2083:"cPanel-SSL",
    2181:"ZooKeeper",2375:"Docker-API",2376:"Docker-API-SSL",
    3128:"Squid-Proxy",3306:"MySQL",3389:"RDP",
    3690:"SVN",4333:"AHCP",4444:"Metasploit",
    4786:"Cisco-Smart-Install",4848:"GlassFish",
    5000:"Docker-Registry",5060:"SIP",5222:"XMPP",
    5353:"mDNS",5432:"PostgreSQL",5555:"Android-ADB",
    5601:"Kibana",5672:"RabbitMQ",5900:"VNC",
    5984:"CouchDB",5985:"WinRM-HTTP",5986:"WinRM-HTTPS",
    6379:"Redis",6443:"Kubernetes-API",6580:"Kaspersky",
    7001:"WebLogic",7077:"Spark",7474:"Neo4j",
    8000:"HTTP-Alt",8001:"HTTP-Alt",8008:"HTTP-Alt",
    8009:"AJP13",8010:"HTTP-Alt",8020:"HTTP-Alt",
    8042:"HTTP-Alt",8060:"HTTP-Alt",8069:"Odoo",
    8070:"HTTP-Alt",8080:"HTTP-Proxy",8081:"HTTP-Alt",
    8082:"HTTP-Alt",8083:"HTTP-Alt",8088:"HTTP-Alt",
    8089:"Splunk",8090:"HTTP-Alt",8091:"HTTP-Alt",
    8092:"HTTP-Alt",8100:"HTTP-Alt",8181:"HTTP-Alt",
    8200:"HTTP-Alt",8222:"HTTP-Alt",8243:"HTTPS-Alt",
    8280:"HTTP-Alt",8300:"HTTP-Alt",8400:"HTTP-Alt",
    8443:"HTTPS-Alt",8484:"HTTP-Alt",8500:"HTTP-Alt",
    8530:"HTTP-Alt",8531:"HTTP-Alt",8806:"HTTP-Alt",
    9000:"PHP-FPM",9042:"Cassandra",9090:"Jenkins",
    9092:"Kafka",9100:"Printer",9200:"Elasticsearch",
    9300:"Elasticsearch-Transport",9418:"Git",
    9999:"HTTP-Alt",10000:"Webmin",11211:"Memcached",
    27017:"MongoDB",27018:"MongoDB-Alt",50070:"HDFS",
    50075:"HDFS-Datanode"
}

SECURITY_CHECKS = {
    21:"FTP Anonymous Login? -> ftp {ip}",
    22:"SSH Weak Credentials? -> hydra -L users.txt -P pass.txt ssh://{ip}",
    23:"Telnet unverschluesselt -> Sniff mit tcpdump",
    25:"SMTP Open Relay? -> nc -nv {ip} 25",
    53:"DNS Zone Transfer? -> dig axfr @{ip}",
    80:"Webserver -> XSS/SQLi? Browser oeffnen",
    110:"POP3 unverschluesselt -> Mitlesen moeglich",
    135:"MSRPC -> RCE? check ms17-010",
    139:"NetBIOS -> Null-Session? -> smbclient -L //{ip}",
    143:"IMAP unverschluesselt -> Passwort Sniffing",
    161:"SNMP Public Community? -> snmpwalk -v2c -c public {ip}",
    389:"LDAP Anonymous Bind? -> ldapsearch -x -h {ip}",
    443:"HTTPS -> Heartbleed? -> python heartbleed-poc.py {ip}",
    445:"SMB -> EternalBlue? -> msfconsole use exploit/windows/smb/ms17_010_eternalblue",
    514:"Syslog -> Log-Informationen abgreifbar?",
    554:"RTSP -> Kamerazugriff? -> ffplay rtsp://{ip}:554",
    587:"SMTP Submission -> Spraying moeglich?",
    631:"IPP -> Druckerzugriff? -> ipptool -tv {ip}",
    873:"Rsync -> Ohne Auth? -> rsync -av rsync://{ip}/",
    993:"IMAPS -> STARTTLS Downgrade?",
    995:"POP3S -> Zertifikatsprobleme?",
    1080:"SOCKS -> Open Proxy? -> curl -x socks5://{ip}:1080 http://ifconfig.me",
    1194:"OpenVPN -> Config verfuegbar?",
    1433:"MSSQL -> SA ohne Passwort? -> sqsh -S {ip} -U sa",
    1521:"Oracle -> Default Accounts?",
    1723:"PPTP -> MSCHAPv2 Crack? -> asleap",
    2049:"NFS -> Showmount? -> showmount -e {ip}",
    2082:"cPanel -> Default Login?",
    2181:"ZooKeeper -> Info? -> echo cons | nc {ip} 2181",
    2375:"Docker -> Unauthorized? -> docker -H tcp://{ip}:2375 ps",
    3128:"Squid -> Open Proxy? -> curl -x http://{ip}:3128 http://ifconfig.me",
    3306:"MySQL -> Root ohne PW? -> mysql -h {ip} -u root",
    3389:"RDP -> BlueKeep (CVE-2019-0708)? -> rdpscan {ip}",
    3690:"SVN -> Repository oeffentlich? -> svn ls svn://{ip}",
    4444:"Metasploit -> Reverse-Shell lauscht?",
    4848:"GlassFish -> Default Admin?",
    5000:"Docker Registry -> API offen? -> curl http://{ip}:5000/v2/_catalog",
    5060:"SIP -> Extension-Enumeration? -> svmap {ip}",
    5222:"XMPP -> User Discovery?",
    5432:"PostgreSQL -> Default Credentials? -> psql -h {ip} -U postgres",
    5555:"ADB -> Android Debug Bridge -> adb connect {ip}:5555",
    5601:"Kibana -> Unauth Access? -> http://{ip}:5601",
    5672:"RabbitMQ -> Default Guest? -> guest:guest",
    5900:"VNC -> No Auth? -> vncviewer {ip}",
    5984:"CouchDB -> Unauth? -> curl http://{ip}:5984",
    5985:"WinRM -> Brute-Force? -> crackmapexec winrm {ip} -u admin -p pass",
    6379:"Redis -> No Auth? -> redis-cli -h {ip} INFO",
    6443:"Kubernetes -> API offen? -> curl -k https://{ip}:6443",
    7001:"WebLogic -> CVE-2017-10271?",
    7077:"Spark -> Unauth Access?",
    7474:"Neo4j -> Default Auth?",
    8000:"HTTP-Alt -> Dirb? -> dirb http://{ip}:8000",
    8080:"HTTP-Proxy -> Tomcat/Jenkins?",
    8089:"Splunk -> Default Admin? -> admin:changeme",
    8443:"HTTPS-Alt -> Zertifikats-Check?",
    9000:"PHP-FPM -> Status-Seite?",
    9090:"Jenkins -> Script-Console?",
    9092:"Kafka -> Topics lesbar?",
    9200:"Elasticsearch -> Unauth? -> curl http://{ip}:9200",
    9300:"Elasticsearch -> Cluster-Zugriff?",
    10000:"Webmin -> RCE? CVE-2019-15107?",
    11211:"Memcached -> Statistik? -> nc -nv {ip} 11211",
    27017:"MongoDB -> No Auth? -> mongosh {ip}:27017"
}

G = Fore.GREEN
Y = Fore.YELLOW
R = Fore.RED
C = Fore.CYAN
W = Fore.WHITE
M = Fore.MAGENTA
B = Style.BRIGHT
RS = Style.RESET_ALL
DIM = Style.DIM

def dc():
    global G,Y,R,C,W,M,B,RS,DIM
    G=Y=R=C=W=M=B=RS=DIM=""

def box(text, color=C, width=60):
    top = color + "+" + "-" * (width - 2) + "+" + RS
    mid = color + "|" + RS + text.center(width - 4) + color + "|" + RS
    bot = color + "+" + "-" * (width - 2) + "+" + RS
    return "\n" + top + "\n" + mid + "\n" + bot + "\n"

def show_banner():
    print(f"""
__________.__                 __            .__                
\______   \  | _____    ____ |  | ____  _  _|__|______   ____  
 |    |  _/  | \__  \ _/ ___\|  |/ /\ \/ \/ /  \_  __ \_/ __ \ 
 |    |   \  |__/ __ \\  \___|    <  \     /|  ||  | \/\  ___/ 
 |______  /____(____  /\___  >__|_ \  \/\_/ |__||__|    \___  >
        \/          \/     \/     \/                        \/ 
        Advanced portscanner for hacker and pentester v3.1
""")

def show_manual():
    print(f"""
{B}{C}╔══════════════════════════════════════════════════════════════════╗{RS}
{B}{C}║{RS}              {B}{W}{APP_NAME} v{VERSION} - HANDBUCH{RS}                     {B}{C}║{RS}
{B}{C}╚══════════════════════════════════════════════════════════════════╝{RS}

{B}{Y}{APP_NAME}{RS} ist ein hochperformanter, multi-threaded TCP-Portscanner
fuer autorisierte Penetration-Tests und Netzwerkadministration.
Enthaelt Portscan, Web-Analyse, Banner-Grabbing, Service-Erkennung,
automatische CVE-Vorschlaege und Sicherheitsempfehlungen.

{B}{Y}BEFEHLE:{RS}
  {C}scan{RS}     Zielhost auf offene Ports scannen
  {C}web{RS}      Web-Analyse: Header + Subdomains + Versionen
  {C}list{RS}     Die 100 haeufigsten Ports anzeigen
  {C}checks{RS}   Sicherheits-Checkliste anzeigen
  {C}version{RS}  Versionsnummer anzeigen

{B}{Y}SCAN-OPTIONEN ({C}scan{RS}{Y}):{RS}
  {C}-t, --target{RS}    IP/HOST     Zieladresse (erforderlich)
  {C}-p, --ports{RS}     PORTS       Port-Spezifikation
  {C}--top-ports{RS}     N           Nur die N haeufigsten Ports
  {C}-n, --threads{RS}   N           Thread-Anzahl (Std: 50)
  {C}--timeout{RS}       SEK         Timeout pro Port (Std: 2.0s)
  {C}--rate-limit{RS}    N/S         Max Verbindungen pro Sekunde
  {C}--no-banner{RS}                 Banner-Grabbing deaktivieren
  {C}--no-color{RS}                  Farben deaktivieren
  {C}--json{RS}          DATEI       Ergebnisse als JSON exportieren
  {C}-v, --verbose{RS}               Ausfuehrliche Ausgabe

{B}{Y}WEB-OPTIONEN ({C}web{RS}{Y}):{RS}
  {C}-t, --target{RS}    DOMAIN      Ziel-Domain (erforderlich)
  {C}--header{RS}                     HTTP-Header analysieren
  {C}--subdomains{RS}                 Subdomains nach Version durchsuchen
  {C}--sub-list{RS}     DATEI        Eigene Subdomain-Liste
  {C}--threads{RS}      N            Threads fuer Subdomain-Scan
  {C}--no-ssl{RS}                     Nur HTTP (kein HTTPS)
  {C}--no-color{RS}                  Farben deaktivieren
  {C}-v, --verbose{RS}               Ausfuehrliche Ausgabe

{B}{Y}BEISPIELE:{RS}
  {C}  blackwire.py scan -t 192.168.1.1{RS}
  {C}  blackwire.py web -t example.com --header --subdomains{RS}
  {C}  blackwire.py -h{RS}
""")

def show_help():
    print(f"""
{B}{C}╔══════════════════════════════════════════════════════════╗{RS}
{B}{C}║{RS}           {B}{W}{APP_NAME} v{VERSION}{RS}                         {B}{C}║{RS}
{B}{C}╚══════════════════════════════════════════════════════════╝{RS}

{B}{Y}USAGE:{RS}  {C}blackwire.py <befehl> [optionen]{RS}

{B}{Y}BEFEHLE:{RS}
  {C}scan{RS}     Zielhost auf offene Ports scannen
  {C}web{RS}      Web-Analyse: Header + Subdomains + Versionen
  {C}list{RS}     Die 100 haeufigsten Ports anzeigen
  {C}checks{RS}   Sicherheits-Checkliste anzeigen
  {C}version{RS}  Versionsnummer anzeigen

{B}{Y}SCAN-OPTIONEN:{RS}
  {C}-t, --target{RS}    IP/HOST     Zieladresse (erforderlich)
  {C}-p, --ports{RS}     PORTS       Port-Spezifikation
  {C}--top-ports{RS}     N           Nur die N haeufigsten Ports
  {C}-n, --threads{RS}   N           Thread-Anzahl (Std: 50)
  {C}--timeout{RS}       SEK         Timeout pro Port (Std: 2.0s)
  {C}--rate-limit{RS}    N/S         Max Verbindungen pro Sekunde
  {C}--no-banner{RS}                 Banner-Grabbing deaktivieren
  {C}--no-color{RS}                  Farben deaktivieren
  {C}--json{RS}          DATEI       Ergebnisse als JSON exportieren
  {C}-v, --verbose{RS}               Ausfuehrliche Ausgabe

{B}{Y}WEB-OPTIONEN:{RS}
  {C}-t, --target{RS}    DOMAIN      Ziel-Domain (erforderlich)
  {C}--header{RS}                     HTTP-Header analysieren
  {C}--subdomains{RS}                 Subdomains nach Version durchsuchen
  {C}--sub-list{RS}     DATEI        Eigene Subdomain-Liste
  {C}--threads{RS}      N            Threads fuer Subdomain-Scan
  {C}--no-ssl{RS}                     Nur HTTP (kein HTTPS)
  {C}--no-color{RS}                  Farben deaktivieren

{B}{Y}BEISPIELE:{RS}
  {C}  blackwire.py scan -t 192.168.1.1{RS}
  {C}  blackwire.py scan -t 10.0.0.1 -p 1-65535 -n 500{RS}
  {C}  blackwire.py web -t example.com --header --subdomains{RS}
  {C}  blackwire.py -h{RS}
""")

def validate_target(target):
    ip_pat = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pat.match(target):
        parts = target.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return target
        print(f"{R}[!] Ungueltige IP-Adresse: {target}{RS}")
        sys.exit(1)
    try:
        ip = socket.gethostbyname(target)
        print(f"{C}[i] {target} -> {ip}{RS}")
        return ip
    except socket.gaierror:
        print(f"{R}[!] Konnte {target} nicht aufloesen.{RS}")
        sys.exit(1)

def parse_ports(port_str):
    ports = set()
    parts = port_str.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                s,e = part.split('-',1)
                s,e = int(s.strip()), int(e.strip())
                if s>e: s,e=e,s
                if s<1 or e>65535:
                    print(f"{R}[!] Port-Bereich {s}-{e} ausserhalb 1-65535{RS}")
                    sys.exit(1)
                ports.update(range(s,e+1))
            except ValueError:
                print(f"{R}[!] Ungueltiger Port-Bereich: {part}{RS}")
                sys.exit(1)
        else:
            try:
                p = int(part)
                if p<1 or p>65535:
                    print(f"{R}[!] Port {p} ausserhalb 1-65535{RS}")
                    sys.exit(1)
                ports.add(p)
            except ValueError:
                print(f"{R}[!] Ungueltiger Port: {part}{RS}")
                sys.exit(1)
    return sorted(ports)

def get_default_ports(top=None):
    if top and top < len(COMMON_PORTS):
        return COMMON_PORTS[:top]
    return COMMON_PORTS

def get_service_name(port):
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        return socket.getservbyport(port,"tcp")
    except:
        return "unknown"

def make_socket(timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s

def is_domain(target):
    ip_pat = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return not bool(ip_pat.match(target))

def grab_http_banner(host, port, timeout=3, use_ssl=False):
    try:
        s = make_socket(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            rs = s
            s = ctx.wrap_socket(rs, server_hostname=host)
        s.connect((host, port))
        s.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
            except: break
        s.close()
        text = resp.decode('utf-8','ignore').strip()
        server_hdr = ""
        for line in text.split('\r\n')[1:]:
            if line.lower().startswith('server:'):
                server_hdr = line.split(':',1)[1].strip()
                break
        status = text.split('\r\n')[0] if text else ""
        return status, server_hdr, text
    except:
        return "", "", ""

def extract_banner_version(banner):
    """Extrahiert (service_name, version) aus einem Banner-String."""
    if not banner:
        return None, None
    patterns = [
        (r'Apache[^/]*/([\d]+\.[\d]+(?:\.[\d]+)?)', 'apache'),
        (r'nginx[^/]*/([\d]+\.[\d]+(?:\.[\d]+)?)', 'nginx'),
        (r'OpenSSH[_-]([\d]+\.[\d]+(?:\.[\d]+)?)', 'openssh'),
        (r'ProFTPD\s+([\d]+\.[\d]+(?:\.[\d]+)?)', 'proftpd'),
        (r'vsftpd\s+([\d]+\.[\d]+(?:\.[\d]+)?)', 'vsftpd'),
        (r'PHP[^/]*/([\d]+\.[\d]+(?:\.[\d]+)?)', 'php'),
        (r'MySQL[^d]*?([\d]+\.[\d]+(?:\.[\d]+)?)', 'mysql'),
        (r'PostgreSQL\s+([\d]+\.[\d]+(?:\.[\d]+)?)', 'postgresql'),
        (r'Redis[^\d]*?v=?([\d]+\.[\d]+(?:\.[\d]+)?)', 'redis'),
        (r'Microsoft SQL Server[^\d]*?(\d{4})', 'mssql'),
        (r'Samba[^\d]*?([\d]+\.[\d]+(?:\.[\d]+)?)', 'samba'),
        (r'Tomcat[^\d]*?([\d]+\.[\d]+(?:\.[\d]+)?)', 'tomcat'),
        (r'WordPress[^\d]*?([\d]+\.[\d]+(?:\.[\d]+)?)', 'wordpress'),
    ]
    for pat, srv in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return srv, m.group(1)
    return None, None

def scan_port(ip, port, timeout, grab=True):
    result = {"port":port,"state":"closed","service":get_service_name(port),"banner":"","reason":""}
    s = None
    try:
        s = make_socket(timeout)
        s.connect((ip,port))
        result["state"] = "open"
        result["reason"] = "syn-ack"
        if not grab:
            try: s.close()
            except: pass
            return result
        if port in (80,8080,8000,8008,8081,8090,8443):
            status, shdr, full = grab_http_banner(ip, port, timeout)
            if shdr:
                result["banner"] = shdr
            elif status:
                result["banner"] = status
            else:
                try:
                    s.settimeout(2)
                    d = s.recv(2048).decode('utf-8','ignore').strip()
                    if d: result["banner"] = d[:200]
                except: pass
        elif port in (443,8443):
            status, shdr, full = grab_http_banner(ip, port, timeout, use_ssl=True)
            if shdr:
                result["banner"] = shdr
            elif status:
                result["banner"] = status
        elif port == 21:
            try:
                s.settimeout(3)
                d = s.recv(2048).decode('utf-8','ignore').strip()
                if d: result["banner"] = d[:300]
                if not result.get("banner"):
                    s.send(b"HELP\r\n")
                    d2 = s.recv(1024).decode('utf-8','ignore').strip()
                    if d2: result["banner"] = d2[:200]
            except: pass
        elif port == 22:
            try:
                s.settimeout(4)
                d = s.recv(2048).decode('utf-8','ignore').strip()
                if d:
                    result["banner"] = d[:300]
                else:
                    s.settimeout(2)
                    d2 = s.recv(2048).decode('utf-8','ignore').strip()
                    if d2: result["banner"] = d2[:300]
            except: pass
        elif port == 25:
            try:
                s.settimeout(3)
                d = s.recv(1024).decode('utf-8','ignore').strip()
                if d: result["banner"] = d[:300]
                if not result.get("banner"):
                    s.send(b"EHLO scanner.local\r\n")
                    d2 = s.recv(1024).decode('utf-8','ignore').strip()
                    if d2: result["banner"] = d2[:200]
            except: pass
        elif port in (110,143):
            try:
                s.settimeout(3)
                d = s.recv(2048).decode('utf-8','ignore').strip()
                if d: result["banner"] = d[:300]
            except: pass
        else:
            try:
                s.settimeout(3)
                d = s.recv(2048).decode('utf-8','ignore').strip()
                if d: result["banner"] = d[:300]
            except: pass
    except socket.timeout: result["reason"]="timeout"
    except ConnectionRefusedError: result["reason"]="refused"
    except OSError as e: result["reason"]=str(e)[:50]
    except: result["reason"]="error"
    finally:
        if s:
            try: s.close()
            except: pass
    return result

def run_scan(ip, ports, threads, timeout, grab_banners, verbose, rate_limit):
    total = len(ports)
    results = []
    rlock = threading.Lock()
    plock = threading.Lock()
    scanned = [0]
    start = time.time()
    last_req = [0.0]
    min_int = 1.0/rate_limit if rate_limit>0 else 0
    def rl_wait():
        if min_int<=0: return
        now=time.time()
        e=now-last_req[0]
        if e<min_int: time.sleep(min_int-e)
        last_req[0]=time.time()
    def show_prog():
        with plock:
            cur = scanned[0]
            if cur>total: cur=total
            pct = (cur/total)*100 if total>0 else 0
            fl = 30
            fi = int(fl*cur/total) if total>0 else 0
            bar = "█"*fi + "░"*(fl-fi)
            el = time.time()-start
            ips = cur/el if el>0 else 0
            sys.stdout.write(f"\r{C}[{bar}]{RS} {C}{cur}/{total}{RS} ({C}{pct:.1f}%{RS}) [{C}{ips:.0f} ports/s{RS}]")
            sys.stdout.flush()
    def scan_wp(port):
        rl_wait()
        res = scan_port(ip,port,timeout,grab_banners)
        with rlock: results.append(res)
        with plock: scanned[0]+=1
        if res["state"]=="open" or scanned[0]%20==0 or scanned[0]==total: show_prog()
        if verbose and res["state"]!="open" and res["reason"] not in ("refused","timeout"):
            sys.stdout.write(f"\n  {Y}[!] Port {port}: {res['reason']}{RS}\n")
            sys.stdout.flush()
        return res
    print(f"\n{W}[*] Starte Scan von {C}{ip}{W} auf {C}{total}{W} Ports ({C}{threads}{W} Threads, {C}{timeout}s{RS}{W} Timeout){RS}\n")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(scan_wp,p):p for p in ports}
        dc = 0
        for ft in as_completed(futs):
            dc+=1
            if dc%50==0 or dc==total: show_prog()
    duration = time.time()-start
    print()
    return results, duration

def show_results(ip, results, duration, threads, use_color=True):
    if use_color:
        g,y,r,c,w,b,rs,d = G,Y,R,C,W,B,RS,DIM
    else:
        g=y=r=c=w=b=rs=d=""
    open_ports = [r for r in results if r["state"]=="open"]
    closed = len(results)-len(open_ports)
    print(f"\n{b}{c}{'='*56}{rs}")
    print(f"{b}{c}  {APP_NAME} v{VERSION} - SCAN RESULTS{rs}")
    print(f"{b}{c}{'='*56}{rs}\n")
    print(f"  {w}Target:{rs}              {c}{ip}{rs}")
    print(f"  {w}Duration:{rs}            {c}{duration:.2f}s{rs}")
    print(f"  {w}Threads:{rs}             {c}{threads}{rs}")
    print(f"  {w}Ports scanned:{rs}       {c}{len(results)}{rs}")
    print(f"  {w}Open ports:{rs}          {g}{len(open_ports)}{rs}")
    print(f"  {w}Closed/Filtered:{rs}     {r}{closed}{rs}")
    print(f"  {w}Scan rate:{rs}           {c}{len(results)/duration:.0f} ports/s{rs}")
    if open_ports:
        print(f"\n  {b}{y}OPEN PORTS{rs} {d}(sorted by port){rs}")
        print(f"  {b}{'─'*56}{rs}")
        print(f"  {d}{'PORT':<8} {'SERVICE':<20} {'BANNER / VERSION'}{rs}")
        print(f"  {d}{'────':<8} {'───────':<20} {'───────────────'}{rs}")
        for r in sorted(open_ports, key=lambda x: x["port"]):
            ps = f"{r['port']}/tcp"
            bs = r['banner'][:65] if r['banner'] else ""
            if not bs:
                bs = f"[{r['service']}]" if r['service']!='unknown' else "-"
            srv_name, srv_ver = extract_banner_version(r['banner'])
            if srv_name and srv_ver:
                print(f"  {g}{ps:<8}{rs} {g}{r['service']:<20}{rs} {c}{bs}{rs}")
            else:
                print(f"  {g}{ps:<8}{rs} {w}{r['service']:<20}{rs} {d}{bs}{rs}")
        recs = []
        for r in open_ports:
            if r['port'] in SECURITY_CHECKS:
                recs.append(SECURITY_CHECKS[r['port']].format(ip=ip))
        if recs:
            print(f"\n  {b}{y}[SECURITY CHECKS]{rs}")
            print(f"  {b}{'─'*56}{rs}")
            for rec in recs[:12]:
                print(f"  {y}→{rs} {rec}")
        cve_entries = []
        for r in sorted(open_ports, key=lambda x: x["port"]):
            banner = r["banner"]
            if not banner: continue
            srv_name, srv_ver = extract_banner_version(banner)
            if srv_name and srv_ver:
                cves = lookup_cves(srv_name, srv_ver)
                if cves:
                    cve_entries.append((r['port'], f"{srv_name} {srv_ver}", cves))
        if cve_entries:
            print(f"\n  {b}{r}[CVE INFORMATION]{rs}")
            print(f"  {b}{'─'*56}{rs}")
            for port, desc, cves in cve_entries:
                print(f"  {g}{port}/tcp{rs} - {c}{desc}{rs}")
                for cve in cves:
                    if cve.startswith("CVE-"):
                        print(f"    {r}▸ {cve}{rs}")
                    else:
                        print(f"    {y}▸ {cve}{rs}")
    print(f"\n{b}{c}{'='*56}{rs}\n")

def export_json(results, ip, duration, threads, filename):
    data = {
        "tool": APP_NAME, "version": VERSION,
        "scan_date": datetime.now().isoformat(),
        "target": ip, "duration_seconds": round(duration,2),
        "threads": threads, "total_ports": len(results),
        "open_ports": len([r for r in results if r["state"]=="open"]),
        "results": sorted(results, key=lambda x: x["port"])
    }
    clean = []
    for r in data["results"]:
        srv_name, srv_ver = extract_banner_version(r['banner'])
        cves = []
        if srv_name and srv_ver:
            cves = lookup_cves(srv_name, srv_ver)
        clean.append({
            "port":r["port"],"state":r["state"],
            "service":r["service"],"banner":r["banner"],
            "reason":r["reason"],"cves":cves
        })
    data["results"] = clean
    try:
        with open(filename,'w',encoding='utf-8') as f:
            json.dump(data,f,indent=2,ensure_ascii=False)
        print(f"{G}[OK] Ergebnisse exportiert nach: {C}{filename}{RS}")
    except IOError as e:
        print(f"{R}[!] Fehler beim Export: {e}{RS}")

def fetch_http_headers(domain, use_ssl=True, timeout=5):
    port = 443 if use_ssl else 80
    headers = {}
    raw = ""
    error = None
    try:
        s = make_socket(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            rs=s; s=ctx.wrap_socket(rs, server_hostname=domain)
        s.connect((domain,port))
        s.send(f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n".encode())
        resp=b""
        while True:
            try:
                chunk=s.recv(4096)
                if not chunk: break
                resp+=chunk
            except: break
        raw=resp.decode('utf-8','ignore')
        lines=raw.split('\r\n')
        for line in lines[1:]:
            if ':' in line:
                k,v=line.split(':',1)
                headers[k.strip().lower()]=v.strip()
        s.close()
    except Exception as e: error=str(e)
    return headers, raw, error

def analyze_headers(domain, use_ssl=True):
    print(f"\n{Y}{B}[*] Header-Analyse fuer: {C}{domain}{RS}\n")
    headers, raw, error = fetch_http_headers(domain, use_ssl)
    if error:
        print(f"  {R}[!] Fehler beim Header-Abruf: {error}{RS}")
        return None
    sl = raw.split('\r\n')[0] if raw else "???"
    print(f"  {W}Status:{RS} {G}{sl}{RS}\n")
    imp=["server","x-powered-by","x-aspnet-version","x-frame-options","x-xss-protection","x-content-type-options","strict-transport-security","content-security-policy","referrer-policy","set-cookie","www-authenticate","location","content-type","x-robots-tag","x-generator","x-drupal-cache","x-varnish","via","x-cache","x-backend"]
    print(f"  {W}{'HEADER':<35} {'VALUE'}{RS}")
    print(f"  {W}{'─'*35} {'─'*30}{RS}")
    for k in imp:
        if k in headers:
            v=headers[k]
            if k in ("server","x-powered-by"):
                print(f"  {G}{k:<35}{RS} {C}{v}{RS}  {Y}← VERSION{RS}")
                srv_name, srv_ver = extract_banner_version(v)
                if srv_name and srv_ver:
                    cves = lookup_cves(srv_name, srv_ver)
                    if cves:
                        for cve in cves:
                            print(f"    {R}▸ {cve}{RS}")
            else:
                print(f"  {C}{k:<35}{RS} {W}{v}{RS}")
    for k,v in sorted(headers.items()):
        if k not in imp: print(f"  {k:<35} {v}")
    print(f"\n  {B}{Y}[SECURITY CHECK]{RS}")
    issues=[]
    if "server" not in headers: issues.append(f"  {G}✓{RS} Server-Version nicht preisgegeben (gut)")
    elif any(c.isdigit() for c in headers.get("server","")): issues.append(f"  {R}✗{RS} Server-Version sichtbar: {headers['server']} (Info-Leak)")
    if "x-frame-options" not in headers: issues.append(f"  {Y}⚠{RS} X-Frame-Options fehlt (Clickjacking moeglich)")
    if "x-xss-protection" not in headers: issues.append(f"  {Y}⚠{RS} X-XSS-Protection fehlt")
    if "x-content-type-options" not in headers: issues.append(f"  {Y}⚠{RS} X-Content-Type-Options fehlt")
    if "strict-transport-security" not in headers and use_ssl: issues.append(f"  {Y}⚠{RS} HSTS fehlt")
    if "content-security-policy" not in headers: issues.append(f"  {Y}⚠{RS} CSP fehlt")
    for iss in issues: print(f"  {iss}")
    return headers

def check_subdomain(domain, sub, timeout=3, use_ssl=True):
    host=f"{sub}.{domain}"
    try:
        ip=socket.gethostbyname(host)
    except: return None
    res={"host":host,"ip":ip,"port":80,"status_raw":"","version_found":None}
    for sport in ([80]+([443] if use_ssl else [])):
        try:
            s=make_socket(timeout)
            if sport==443:
                ctx=ssl.create_default_context()
                ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                rs=s; s=ctx.wrap_socket(rs, server_hostname=host)
            s.connect((host,sport))
            s.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            resp=b""
            while True:
                try:
                    c=s.recv(4096)
                    if not c: break
                    resp+=c
                except: break
            s.close()
            raw=resp.decode('utf-8','ignore')
            res["port"]=sport
            res["status_raw"]=raw.split('\r\n')[0] if raw else "???"
            for line in raw.split('\r\n')[1:]:
                if line.lower().startswith('server:'):
                    ver=line.split(':',1)[1].strip()
                    if ver and ver!="unknown":
                        res["version_found"]=ver
                        return res
        except: pass
    return res

def scan_subdomains(domain, sublist, threads=50, use_ssl=True, verbose=False):
    print(f"\n{Y}{B}[*] Subdomain-Scan fuer: {C}{domain}{RS}")
    print(f"  {W}Teste {len(sublist)} Subdomains mit {threads} Threads...{RS}\n")
    results=[]
    rlock=threading.Lock()
    def scan_sub(sub):
        res=check_subdomain(domain,sub,use_ssl=use_ssl)
        if res:
            proto="HTTPS" if res["port"]==443 else "HTTP"
            v=res.get("version_found","")
            if v:
                print(f"  {G}[+] {res['host']:<40} {C}{res['ip']:<16}{RS} {Y}{proto}{RS} → {C}{v}{RS}")
            elif verbose:
                print(f"  {W}[~] {res['host']:<40} {res['ip']:<16} {proto} (no version){RS}")
            return res
        return None
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs={ex.submit(scan_sub,sub):sub for sub in sublist}
        for ft in as_completed(futs):
            r=ft.result()
            if r:
                with rlock: results.append(r)
    results=sorted(results,key=lambda x:x["host"])
    vo=[r for r in results if r.get("version_found")]
    soo=[r for r in results if not r.get("version_found")]
    print(f"\n  {B}{C}{'='*56}{RS}")
    print(f"  {W}Total subdomains found:{RS} {C}{len(results)}{RS}")
    print(f"  {W}With server version:{RS}   {G}{len(vo)}{RS}")
    print(f"  {W}Without version:{RS}        {Y}{len(soo)}{RS}")
    print(f"  {B}{C}{'='*56}{RS}\n")
    if len(vo)==1:
        r=vo[0]
        print(f"  {B}{Y}{'!'*56}{RS}")
        print(f"  {B}{R}[!] EXCLUSIVE VERSION on SINGLE subdomain!{RS}")
        print(f"  {B}{C}  Host:    {r['host']}{RS}")
        print(f"  {B}{C}  IP:      {r['ip']}{RS}")
        print(f"  {B}{C}  Version: {r['version_found']}{RS}")
        srv_name, srv_ver = extract_banner_version(r['version_found'])
        if srv_name and srv_ver:
            cves = lookup_cves(srv_name, srv_ver)
            if cves:
                print(f"  {B}{R}  CVEs:{RS}")
                for cve in cves:
                    print(f"    {Y}▸ {cve}{RS}")
        print(f"  {B}{Y}{'!'*56}{RS}\n")
    elif len(vo)>1:
        print(f"  {B}{Y}Subdomains WITH server version:{RS}\n")
        print(f"  {'SUBDOMAIN':<40} {'IP':<18} {'VERSION'}")
        print(f"  {'─────────':<40} {'──':<18} {'───────'}")
        for r in vo:
            print(f"  {G}{r['host']:<40}{RS} {C}{r['ip']:<18}{RS} {Y}{r['version_found']}{RS}")
        print(f"\n  {B}{Y}CVE lookup:{RS}")
        for r in vo:
            ver=r.get("version_found","")
            if not ver: continue
            srv_name, srv_ver = extract_banner_version(ver)
            if srv_name and srv_ver:
                cves = lookup_cves(srv_name, srv_ver)
                if cves:
                    print(f"\n  {C}{r['host']}{RS} - {Y}{ver}{RS}")
                    for cve in cves:
                        print(f"    {R}▸ {cve}{RS}")
                else:
                    print(f"\n  {C}{r['host']}{RS} - {Y}{ver}{RS} {DIM}(no CVEs in database){RS}")
    else:
        print(f"  {Y}No subdomain with server version found.{RS}")
    if soo and verbose:
        print(f"\n  {W}Subdomains WITHOUT version:{RS}\n")
        for r in soo:
            print(f"  {W}{r['host']:<45} {r['ip']:<18} ({r['status_raw']}){RS}")
    return results

def run_web_analysis(domain, do_header, do_subdomains, sub_list_file, threads, use_ssl, verbose):
    print(f"\n{B}{C}{'='*56}{RS}")
    print(f"{B}{C}  WEB ANALYSIS - {domain}{RS}")
    print(f"{B}{C}{'='*56}{RS}")
    try:
        ip=socket.gethostbyname(domain)
        print(f"\n{C}[i] {domain} -> {ip}{RS}")
    except:
        print(f"{R}[!] Could not resolve {domain}.{RS}")
        sys.exit(1)
    if do_header:
        analyze_headers(domain, use_ssl)
    if do_subdomains:
        if sub_list_file:
            try:
                with open(sub_list_file,'r') as f:
                    subs=[l.strip() for l in f if l.strip() and not l.startswith('#')]
                print(f"\n{C}[i] Custom subdomain list loaded: {len(subs)} entries{RS}")
            except:
                print(f"{R}[!] Could not read file.{RS}")
                sys.exit(1)
        else:
            subs=COMMON_SUBDOMAINS
            print(f"\n{C}[i] Default subdomain list: {len(subs)} entries{RS}")
        scan_subdomains(domain, subs, threads, use_ssl, verbose)

def show_port_list():
    print(f"\n{B}{C}Top 100 TCP Ports{RS}\n")
    for i in range(0,len(COMMON_PORTS),10):
        grp=COMMON_PORTS[i:i+10]
        ln="  ".join(f"{C}{p:<5}{RS}" for p in grp)
        hints="  │  "+", ".join(PORT_SERVICES.get(p,"")[:12] for p in grp)
        print(f"  {ln}{hints}")
    print(f"\n{Y}Total: {len(COMMON_PORTS)} ports{RS}\n")

def show_checks():
    print(f"\n{B}{C}All Security Checks{RS}\n")
    print(f"  {'PORT':<8} {'SERVICE':<18} {'CHECK'}")
    print(f"  {'────':<8} {'───────':<18} {'─────'}")
    for p in sorted(SECURITY_CHECKS.keys()):
        svc=PORT_SERVICES.get(p,"unknown")
        chk=SECURITY_CHECKS[p]
        print(f"  {C}{p:<8}{RS} {W}{svc:<18}{RS} {Y}{chk}{RS}")
    print(f"\n{Y}Total: {len(SECURITY_CHECKS)} checks{RS}\n")

def show_version():
    print(f"\n{C}{APP_NAME} v{VERSION}{RS}")
    print(f"{W}  Python {sys.version.split()[0]}{RS}")
    print(f"{W}  Developed for authorized security testing{RS}\n")

def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd in ("-h","--help","help"):
            show_help()
            return
        elif cmd == "list":
            show_port_list()
            return
        elif cmd == "checks":
            show_checks()
            return
        elif cmd in ("version","--version"):
            show_version()
            return
        if cmd == "web":
            sys.argv.pop(1)
            wp = argparse.ArgumentParser(description='Web Analysis', add_help=False)
            wp.add_argument('-t','--target',type=str,required=True,help='Target domain')
            wp.add_argument('--header',action='store_true',help='Analyze HTTP headers')
            wp.add_argument('--subdomains',action='store_true',help='Scan subdomains')
            wp.add_argument('--sub-list',type=str,help='Custom subdomain list file')
            wp.add_argument('--threads',type=int,default=50,help='Threads (default: 50)')
            wp.add_argument('--no-ssl',action='store_true',help='HTTP only (no HTTPS)')
            wp.add_argument('--no-color',action='store_true',help='Disable colors')
            wp.add_argument('-v','--verbose',action='store_true',help='Verbose output')
            try: wa = wp.parse_args()
            except:
                print(f"\n{Y}Tip: {C}blackwire.py web -t example.com --header --subdomains{RS}\n")
                sys.exit(1)
            if wa.no_color: dc()
            if not wa.header and not wa.subdomains:
                print(f"{Y}[!] Please specify --header and/or --subdomains.{RS}")
                sys.exit(1)
            if not is_domain(wa.target):
                print(f"{R}[!] Web analysis requires a domain name, not an IP.{RS}")
                sys.exit(1)
            show_banner()
            run_web_analysis(wa.target, wa.header, wa.subdomains, wa.sub_list, wa.threads, not wa.no_ssl, wa.verbose)
            return
    if len(sys.argv) == 1:
        show_manual()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        sys.argv.pop(1)
    parser = argparse.ArgumentParser(description=f'{APP_NAME} v{VERSION}', add_help=False)
    parser.add_argument('command', nargs='?', choices=['scan'], help='Scan command')
    parser.add_argument('-t','--target',type=str,required=True,help='Target IP or hostname')
    parser.add_argument('-p','--ports',type=str,help='Port specification')
    parser.add_argument('--top-ports',type=int,help='Only scan top N ports')
    parser.add_argument('-n','--threads',type=int,default=50,help='Threads (default: 50)')
    parser.add_argument('--timeout',type=float,default=2.0,help='Timeout per port (default: 2.0s)')
    parser.add_argument('--no-banner',action='store_true',help='Disable banner grabbing')
    parser.add_argument('--no-color',action='store_true',help='Disable colors')
    parser.add_argument('-v','--verbose',action='store_true',help='Verbose output')
    parser.add_argument('--json',type=str,metavar='FILE',help='Export results as JSON')
    parser.add_argument('--rate-limit',type=int,default=0,help='Max connections/second (0=unlimited)')
    try: args = parser.parse_args()
    except:
        print(f"\n{Y}Tip: {C}blackwire.py -h{RS}\n")
        sys.exit(1)
    if args.no_color: dc()
    show_banner()
    ip = validate_target(args.target)
    if args.ports:
        ports = parse_ports(args.ports)
        print(f"{C}[i] Custom ports: {len(ports)} ports{RS}")
    elif args.top_ports:
        ports = get_default_ports(args.top_ports)
        print(f"{C}[i] Top-{args.top_ports} ports: {len(ports)} ports{RS}")
    else:
        ports = get_default_ports()
        print(f"{C}[i] Default (top-100 ports): {len(ports)} ports{RS}")
    max_threads = min(args.threads, len(ports))
    if max_threads < 1: max_threads = 1
    if len(ports) > 5000:
        print(f"{Y}[!] Large port range ({len(ports)} ports). This may take a while.{RS}")
    results, duration = run_scan(ip, ports, max_threads, args.timeout, not args.no_banner, args.verbose, args.rate_limit)
    show_results(ip, results, duration, max_threads, use_color=not args.no_color)
    if args.json:
        export_json(results, ip, duration, max_threads, args.json)
    open_count = len([r for r in results if r["state"]=="open"])
    if open_count == 0:
        print(f"{Y}[!] No open ports found. Firewall blocking? Try wider port range.{RS}")
    print(f"{G}[OK] Scan completed in {duration:.2f}s{RS}\n")

if __name__ == "__main__":
    main()