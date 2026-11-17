"""The MITRE ATT&CK techniques the USB rules use: names, tactics, links (for Sigma tags and Elastic threat maps).

Checked against attack.mitre.org on 2026-11-17 (ATT&CK v18): TA0005 is now "Stealth", "Defense Impairment" (TA0112)
is new, and Clear Windows Event Logs moved from T1070.001 to T1685.005 (as SigmaHQ's current rules tag it).
"""

TACTICS = {   # id -> (name, Sigma/Elastic short name)
    "TA0001": ("Initial Access", "initial-access"),
    "TA0003": ("Persistence", "persistence"),
    "TA0005": ("Stealth", "stealth"),
    "TA0008": ("Lateral Movement", "lateral-movement"),
    "TA0009": ("Collection", "collection"),
    "TA0010": ("Exfiltration", "exfiltration"),
    "TA0040": ("Impact", "impact"),
    "TA0112": ("Defense Impairment", "defense-impairment"),
}

TECHNIQUES = {   # id -> (name, [tactic ids])
    "T1052": ("Exfiltration Over Physical Medium", ["TA0010"]),
    "T1052.001": ("Exfiltration over USB", ["TA0010"]),
    "T1070": ("Indicator Removal", ["TA0005"]),
    "T1091": ("Replication Through Removable Media", ["TA0001", "TA0008"]),
    "T1112": ("Modify Registry", ["TA0003", "TA0112"]),
    "T1200": ("Hardware Additions", ["TA0001"]),
    "T1560": ("Archive Collected Data", ["TA0009"]),
    "T1561": ("Disk Wipe", ["TA0040"]),
    "T1685": ("Disable or Modify Tools", ["TA0112"]),
    "T1685.001": ("Disable or Modify Windows Event Log", ["TA0112"]),
    "T1685.005": ("Clear Windows Event Logs", ["TA0112"]),
}


def url(technique_or_tactic: str) -> str:
    if technique_or_tactic.startswith("TA"):
        return f"https://attack.mitre.org/tactics/{technique_or_tactic}/"
    return "https://attack.mitre.org/techniques/" + technique_or_tactic.replace(".", "/") + "/"


def tactics_of(technique: str) -> list[str]:
    return TECHNIQUES[technique][1]


def tactic_names(techniques: list[str]) -> list[str]:
    seen = []
    for t in techniques:
        for ta in tactics_of(t):
            if TACTICS[ta][0] not in seen:
                seen.append(TACTICS[ta][0])
    return seen


def sigma_tags(techniques: list[str]) -> list[str]:
    tags = []
    for t in techniques:
        for ta in tactics_of(t):
            if f"attack.{TACTICS[ta][1]}" not in tags:
                tags.append(f"attack.{TACTICS[ta][1]}")
    return tags + [f"attack.{t.lower()}" for t in techniques]


def elastic_threat(techniques: list[str]) -> list[dict]:
    """Elastic Security `threat` array: tactic -> techniques -> subtechniques."""
    by_tactic: dict[str, dict[str, dict]] = {}
    for t in techniques:
        parent = t.split(".")[0]
        for ta in tactics_of(t):
            entries = by_tactic.setdefault(ta, {})
            entry = entries.setdefault(parent, {"id": parent, "name": TECHNIQUES[parent][0], "reference": url(parent)})
            if "." in t:
                subs = entry.setdefault("subtechnique", [])
                if not any(s["id"] == t for s in subs):
                    subs.append({"id": t, "name": TECHNIQUES[t][0], "reference": url(t)})
    return [{"framework": "MITRE ATT&CK",
             "tactic": {"id": ta, "name": TACTICS[ta][0], "reference": url(ta)},
             "technique": list(techs.values())} for ta, techs in by_tactic.items()]
