from __future__ import annotations
import re

# Expanded APT/threat actor patterns
APT_RE = re.compile(
    r"\bAPT\s?\d+\b"
    r"|\bFIN\d+\b"
    r"|\bTA\d+\b"
    r"|\bUNC\d+\b"
    r"|\bLazarus\s*(Group)?\b"
    r"|\bSandworm\b"
    r"|\bCozy\s*Bear\b"
    r"|\bFancy\s*Bear\b"
    r"|\bVolt\s*Typhoon\b"
    r"|\bSalt\s*Typhoon\b"
    r"|\bFlax\s*Typhoon\b"
    r"|\bScattered\s*Spider\b"
    r"|\bBlackCat\b"
    r"|\bAlphv\b"
    r"|\bLockBit\b"
    r"|\bCl0p\b|\\bClop\b"
    r"|\bHive\s*(Ransomware)?\b"
    r"|\bConti\b"
    r"|\bREvil\b"
    r"|\bDarkSide\b"
    r"|\bKimsuky\b"
    r"|\bMuddy\s*Water\b"
    r"|\bTurla\b"
    r"|\bBerserk\s*Bear\b"
    r"|\bGambaredon\b"
    r"|\bSilver\s*Fox\b"
    r"|\bEarth\s*\w+\b",
    re.IGNORECASE
)

# Expanded malware families
MALWARE_RE = re.compile(
    r"\bEmotet\b"
    r"|\bTrickBot\b"
    r"|\bQakBot\b|\\bQbot\b"
    r"|\bMirai\b"
    r"|\bCobalt\s*Strike\b"
    r"|\bMimikatz\b"
    r"|\bSliver\b"
    r"|\bBrute\s*Ratel\b"
    r"|\bMetasploit\b"
    r"|\bNjRAT\b"
    r"|\bAsyncRAT\b"
    r"|\bAgent\s*Tesla\b"
    r"|\bFormbook\b"
    r"|\bRedLine\b"
    r"|\bInfostealer\b"
    r"|\bRaccoon\b"
    r"|\bVidar\b"
    r"|\bLumma\b"
    r"|\bStealc\b"
    r"|\bDarkComet\b"
    r"|\bNetWire\b"
    r"|\bIcedID\b"
    r"|\bBazarLoader\b"
    r"|\bSystemBC\b"
    r"|\bHavoc\b"
    r"|\bNightHawk\b"
    r"|\bGolang\s*backdoor\b"
    r"|\bWebShell\b|\\bWeb\s*Shell\b"
    r"|\bRansomware\b"
    r"|\bWiper\b"
    r"|\bRootkit\b"
    r"|\bKeylogger\b"
    r"|\bDropper\b"
    r"|\bLoader\b",
    re.IGNORECASE
)

VERSION_CORE = r"(?:v)?(\d{1,4}\.\d{1,4}(?:\.\d{1,6})?)"
VERSION_X = r"(?:v)?(\d{1,4}\.\d{1,4}\.x)"

VERSION_RE = re.compile(rf"\b(?:{VERSION_CORE}|{VERSION_X})\b", re.IGNORECASE)

RANGE_RE = re.compile(
    rf"\b(<=|>=|<|>|before|prior to|earlier than|through)\s*(\d{{1,4}}\.\d{{1,4}}(?:\.\d{{1,6}})?)\b",
    re.IGNORECASE
)

PRODUCT_VERSION_LINE_RE = re.compile(
    rf"\b(versions?|releases?)\b[^.\n]*\b(\d{{1,4}}\.\d{{1,4}}(?:\.\d{{1,6}})?|(?:v)?\d{{1,4}}\.\d{{1,4}}\.x)\b",
    re.IGNORECASE
)


def extract_versions(text: str) -> list[str]:
    t = text or ""
    found = set()
    for m in VERSION_RE.finditer(t):
        val = m.group(1) or m.group(2) or ""
        if val:
            found.add(val)
    for m in RANGE_RE.finditer(t):
        op = m.group(1).lower()
        ver = m.group(2)
        found.add(f"{op} {ver}")
    for m in PRODUCT_VERSION_LINE_RE.finditer(t):
        found.add(m.group(2))
    return sorted(v.replace("V", "v") for v in found)[:20]


def extract_apts(text: str) -> list[str]:
    out = set()
    for m in APT_RE.finditer(text or ""):
        out.add(re.sub(r"\s+", " ", m.group(0)).strip())
    return sorted(out)[:15]


def extract_malware(text: str) -> list[str]:
    out = set()
    for m in MALWARE_RE.finditer(text or ""):
        out.add(re.sub(r"\s+", " ", m.group(0)).strip())
    return sorted(out)[:15]
