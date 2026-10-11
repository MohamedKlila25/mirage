"""ATT&CK technique per event, from simple command patterns (plan section 10, starting table).

Deterministic and readable on purpose: it feeds the techniques-observed metric and the
timeline. First match wins, so specific patterns come before generic ones.
"""
from __future__ import annotations

import re

# first match wins -> specific/evasion/exfil patterns come before generic discovery ones.
COMMAND_RULES: list[tuple[str, str]] = [
    # --- defense evasion ---
    ("T1070.006", r"\btouch\b\s+-[a-z]*(t|d)\b"),                              # Indicator Removal: Timestomp
    ("T1070.003", r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|rm\b[^|]*\.bash_history"),  # Clear Command History
    ("T1070.004", r"\brm\b\s+-[rf]+\b[^|]*(/tmp|/var/log|\.log)"),             # Indicator Removal: File Deletion
    # --- persistence ---
    ("T1546.004", r">>\s*~?/?\.?(bashrc|bash_profile|profile)|/etc/profile"),  # Unix Shell Config Modification
    ("T1098.004", r"authorized_keys"),                                         # SSH Authorized Keys
    ("T1136.001", r"\b(useradd|adduser)\b"),                                   # Create Local Account
    ("T1053.003", r"\bcrontab\b|/etc/cron"),                                   # Scheduled Task: Cron
    # --- privilege escalation ---
    ("T1548.003", r"\bsudo\s+(su|-i|-s|bash|sh)\b|(^|[;&|]\s*)su\s+-?"),       # Sudo / elevation
    ("T1548.001", r"-perm\s+-?/?u?\+?s?[0-7]*4000|\bgetcap\b"),                # SUID/SGID abuse
    # --- lateral movement ---
    ("T1021.004", r"(^|[;&|]\s*)(ssh|scp|sftp|sshpass)\s"),                    # Remote Services: SSH
    # --- exfiltration / transfer / encoding ---
    ("T1041", r"\b(curl|wget)\b[^|]*(-F|-d\b|--data|-T\b|-X\s*POST|@/)"),      # Exfiltration Over C2/Web
    ("T1132.001", r"\bbase64\b|\bxxd\b|\bopenssl\b\s+enc"),                    # Data Encoding
    ("T1105", r"\b(wget|curl|tftp|nc|ncat)\b"),                                # Ingress Tool Transfer
    # --- collection ---
    ("T1005", r"\b(mysqldump|pg_dump|mongodump)\b|\bcp\b[^|]*\.(sql|db|sqlite|dump)\b|\bcat\b[^|]*\.(sql|dump)\b"),  # Data from Local System
    ("T1560.001", r"\b(tar|zip|gzip|7z|rar)\s"),                               # Archive Collected Data
    # --- account / group discovery (before cred rules: /etc/passwd contains 'passw') ---
    ("T1087.001", r"/etc/passwd\b|\bgetent\s+passwd\b"),                       # Account Discovery: Local
    ("T1069.001", r"/etc/group\b|(^|[;&|]\s*)groups(\s|$)|\bgetent\s+group\b"),  # Permission Groups Discovery
    # --- credential access ---
    ("T1552.004", r"\bid_rsa\b|\.pem\b|\.key\b|private.?key|\.ppk\b"),         # Unsecured Credentials: Private Keys
    ("T1552.003", r"\.bash_history\b"),                                        # Credentials in Bash History
    ("T1552.001", r"\.env\b|credential|passw|\.aws/|secret|\.pgpass|config\.(json|ya?ml)|backup[^|]*\.sql|grep[^|]*passw"),  # Creds in Files
    # --- discovery ---
    ("T1518", r"\b(dpkg|rpm|apt|yum|snap)\b\s*(-l|list|-qa)|\bpip\b\s+list"),  # Software Discovery
    ("T1007", r"\b(systemctl|service|initctl)\b"),                             # System Service Discovery
    ("T1057", r"(^|[;&|]\s*)(ps|top|htop)(\s|$)|\bpgrep\b"),                   # Process Discovery
    ("T1049", r"\b(netstat|ss)\b"),                                            # Network Connections Discovery
    ("T1016", r"\b(ifconfig|route|arp)\b|\bip\s+(a|addr|r|route|link)\b|/etc/(hosts|resolv)"),  # Network Config Discovery
    ("T1082", r"\b(uname|hostnamectl|lsb_release|hostname|lscpu|dmidecode|mount|lsblk)\b|/etc/os-release|/proc/version|(^|[;&|]\s*)(df|env)(\s|$)"),  # System Information Discovery
    ("T1033", r"(^|[;&|]\s*)(whoami|id|w|who|last|logname)(\s|$)|\bsudo\s+-l\b"),  # System Owner/User Discovery
    ("T1083", r"(^|[;&|]\s*)(ls|find|tree|locate|stat|du)(\s|$)"),             # File and Directory Discovery
]
_COMPILED = [(t, re.compile(rx, re.IGNORECASE)) for t, rx in COMMAND_RULES]

EVENT_RULES = {"login": "T1078", "login_failed": "T1110", "canary_use": "T1078"}


def technique_for(event_type: str, content: str) -> str | None:
    if event_type in EVENT_RULES:
        return EVENT_RULES[event_type]
    if event_type == "command":
        for tech, rx in _COMPILED:
            if rx.search(content or ""):
                return tech
    return None
