from __future__ import annotations

"""
MITRE ATT&CK rules.
Format: ([keywords], technique_id, technique_name, tactic, confidence_0_100)
"""

RULES = [
    # Initial Access
    (["exploit", "exploitation", "authentication bypass", "rce", "remote code execution",
      "unauthenticated", "pre-auth", "public-facing"],
     "T1190", "Exploit Public-Facing Application", "initial-access", 80),

    (["phishing", "spearphishing", "email lure", "malicious attachment", "malicious link"],
     "T1566", "Phishing", "initial-access", 75),

    (["supply chain", "third-party", "dependency", "npm package", "pypi package"],
     "T1195", "Supply Chain Compromise", "initial-access", 70),

    (["vpn", "remote access", "exposed rdp", "rdp brute", "exposed service"],
     "T1133", "External Remote Services", "initial-access", 65),

    # Execution
    (["powershell", "ps1", "invoke-expression", "iex"],
     "T1059.001", "PowerShell", "execution", 80),

    (["cmd.exe", "wscript", "cscript", "mshta", "rundll32"],
     "T1059.003", "Windows Command Shell", "execution", 75),

    (["bash", "sh ", "/bin/sh", "curl | bash", "wget | sh"],
     "T1059.004", "Unix Shell", "execution", 70),

    (["macro", "office macro", "vba", "xlsm", "docm"],
     "T1059.005", "Visual Basic", "execution", 75),

    # Persistence
    (["persistence", "startup", "registry run", "scheduled task", "cron job", "autostart"],
     "T1547", "Boot or Logon Autostart Execution", "persistence", 65),

    (["web shell", "webshell", "jsp shell", "php shell"],
     "T1505.003", "Web Shell", "persistence", 85),

    (["backdoor", "implant", "trojan"],
     "T1543", "Create or Modify System Process", "persistence", 60),

    # Privilege Escalation
    (["privilege escalation", "local privilege", "lpe", "sudo exploit", "suid"],
     "T1068", "Exploitation for Privilege Escalation", "privilege-escalation", 75),

    # Defense Evasion
    (["valid account", "valid accounts", "credential", "credentials", "stolen credentials",
      "default password", "password reuse", "account takeover", "brute force"],
     "T1078", "Valid Accounts", "defense-evasion", 70),

    (["obfuscation", "encode", "base64", "encrypted payload", "packed"],
     "T1027", "Obfuscated Files or Information", "defense-evasion", 65),

    (["disable defender", "disable av", "disable logging", "tamper protection"],
     "T1562", "Impair Defenses", "defense-evasion", 75),

    # Credential Access
    (["mimikatz", "lsass", "credential dumping", "ntds.dit", "pass the hash", "kerberoasting"],
     "T1003", "OS Credential Dumping", "credential-access", 85),

    # Discovery
    (["network scan", "port scan", "nmap", "masscan", "reconnaissance"],
     "T1046", "Network Service Discovery", "discovery", 65),

    # Lateral Movement
    (["lateral movement", "psexec", "wmi", "remote service", "pass the ticket"],
     "T1021", "Remote Services", "lateral-movement", 65),

    # C2
    (["command and control", "c2", "beacon", "callback", "cobalt strike", "sliver", "brute ratel"],
     "T1071", "Application Layer Protocol", "command-and-control", 70),

    (["dns tunneling", "dns c2", "dns exfil"],
     "T1071.004", "DNS", "command-and-control", 75),

    # Exfiltration
    (["exfiltration", "data theft", "steal data", "data breach", "data leak"],
     "T1041", "Exfiltration Over C2 Channel", "exfiltration", 65),

    # Impact
    (["ransomware", "encrypt files", "ransom note", "lockbit", "cl0p", "alphv", "blackcat"],
     "T1486", "Data Encrypted for Impact", "impact", 90),

    (["wiper", "destructive", "data destruction", "delete backups", "vss delete"],
     "T1485", "Data Destruction", "impact", 85),

    (["ddos", "denial of service", "dos attack", "flood"],
     "T1498", "Network Denial of Service", "impact", 70),
]

# Defensive recommendations per technique
MITRE_DEFENSES = {
    "T1190": "Patcher les services exposés, restreindre l'accès réseau, activer le WAF.",
    "T1566": "Formation anti-phishing, filtrage email, MFA, sandboxing des pièces jointes.",
    "T1195": "Audit des dépendances, SCA (Software Composition Analysis), SBOM.",
    "T1133": "MFA sur tous les accès distants, VPN avec authentification forte, audit des comptes.",
    "T1059.001": "Restreindre PowerShell (WDAC/AppLocker), activer ScriptBlock Logging, utiliser Constrained Language Mode.",
    "T1059.003": "Contrôle des processus enfants, EDR avec protection comportementale.",
    "T1059.004": "Minimiser les shells exposés, audit des scripts cron, surveillance des exécutions.",
    "T1059.005": "Désactiver les macros Office, utiliser Protected View, formation utilisateurs.",
    "T1547": "Audit des clés Run, surveillance des tâches planifiées, EDR.",
    "T1505.003": "Scanner les répertoires web, intégrité des fichiers (FIM), journaux d'accès.",
    "T1543": "Surveillance des services système, contrôle d'intégrité.",
    "T1068": "Appliquer les patches système rapidement, principe du moindre privilège.",
    "T1078": "MFA, rotation des mots de passe, alertes sur connexions inhabituelles.",
    "T1027": "Analyse comportementale (EDR/SIEM), décodage automatique des payloads suspects.",
    "T1562": "Protéger les solutions de sécurité contre la modification (tamper protection).",
    "T1003": "Activer Credential Guard, surveiller les accès LSASS, MFA.",
    "T1046": "Segmentation réseau, surveillance des scans, filtrage des sorties.",
    "T1021": "Restreindre SMB/WMI/RDP inter-segments, surveillance des mouvements latéraux.",
    "T1071": "Inspection TLS, proxy web, détection beacon via analyse réseau.",
    "T1071.004": "Filtrer le DNS sortant, détecter les anomalies de requêtes DNS.",
    "T1041": "DLP, surveillance des flux sortants, segmentation réseau.",
    "T1486": "Sauvegardes hors ligne testées, EDR anti-ransomware, segmentation.",
    "T1485": "Sauvegardes immuables, surveillance des suppressions de masse, EDR.",
    "T1498": "Anti-DDoS (CDN/scrubbing), rate-limiting, monitoring réseau.",
}
