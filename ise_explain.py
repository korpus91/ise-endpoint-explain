#!/usr/bin/env python3
"""
ise-endpoint-explain: why did this endpoint get what it got?

Pulls one MAC address's live session and recent authentication history from the
Cisco ISE Monitoring (MnT) REST API and prints a plain-English timeline: pass or
fail, who, how, where, which authorization profile and SGT, and for failures the
ISE failure reason with a likely cause.

Read-only. Two GET calls against the MnT node:
  GET /admin/API/mnt/Session/MACAddress/{mac}
  GET /admin/API/mnt/AuthStatus/MACAddress/{mac}/{seconds}/{records}/All

Offline mode (--offline DIR) reads saved XML (session.xml, authstatus.xml), so a
client can run the two calls and send you the output without granting access.

Exit codes: 0 last authentication passed, 1 last authentication failed or no
records, 2 error.
"""
import argparse
import getpass
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_SECONDS = 432000  # ISE MnT limit: 5 days

# Common ISE failure reason codes and the usual cause. Matched on the leading number.
HINTS = {
    "5400": "Generic authentication failure. Read the failure reason text and the ISE live log steps.",
    "5411": "Supplicant stopped responding. Usually the client does not trust the ISE EAP certificate, or the supplicant profile is wrong.",
    "5440": "Endpoint abandoned the EAP session and started a new one. Often a supplicant timing or certificate prompt issue.",
    "11036": "Message-Authenticator invalid. RADIUS shared secret mismatch between the network device and ISE.",
    "12321": "PEAP TLS handshake failed because the client rejected the ISE certificate. Check the EAP certificate chain and client trust.",
    "12514": "EAP-TLS handshake failed on an unknown CA in the client certificate chain. Import the issuing CA into ISE trusted certificates for client auth.",
    "12935": "Supplicant stopped responding during the EAP-TLS certificate exchange. Check client certificate and trust.",
    "15039": "Rejected per authorization profile. The matched authorization rule returned DenyAccess.",
    "22040": "Wrong password or invalid shared secret.",
    "22056": "Subject not found in the identity store. Unknown user, or for MAB an endpoint not in the expected identity group.",
    "24408": "Active Directory rejected the password.",
}


def strip_ns(tag: str) -> str:
    return tag.split("}", 1)[-1]


def element_to_dict(el) -> dict:
    """Flatten one record: child tag -> text. Unknown fields are kept, so nothing is lost."""
    out = {}
    for c in el:
        if len(c):
            continue
        out[strip_ns(c.tag).lower()] = (c.text or "").strip()
    return out


def parse_other_attrs(s: str) -> dict:
    """other_attr_string holds key=value pairs separated by ':!:' or commas."""
    attrs = {}
    for part in re.split(r":!:|,(?=[A-Za-z][\w-]*=)", s or ""):
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.strip()] = v.strip()
    return attrs


def parse_authstatus(xml_text: str) -> list:
    root = ET.fromstring(xml_text)
    records = []
    for el in root.iter():
        if strip_ns(el.tag) == "authStatusElements":
            rec = element_to_dict(el)
            rec["_attrs"] = parse_other_attrs(rec.get("other_attr_string", ""))
            records.append(rec)
    records.sort(key=lambda r: r.get("acs_timestamp") or r.get("acsview_timestamp") or "", reverse=True)
    return records


def parse_session(xml_text: str) -> dict:
    if not xml_text or not xml_text.strip():
        return {}
    root = ET.fromstring(xml_text)
    return element_to_dict(root) if strip_ns(root.tag) == "sessionParameters" else {}


def first(rec: dict, *keys, default="-") -> str:
    for k in keys:
        v = rec.get(k) or rec.get("_attrs", {}).get(k)
        if v:
            return v
    return default


def hint(reason: str) -> str:
    m = re.match(r"\s*(\d+)", reason or "")
    return HINTS.get(m.group(1), "") if m else ""


def passed(rec: dict) -> bool:
    return first(rec, "passed", default="false").lower() == "true"


def render(mac: str, session: dict, records: list) -> str:
    lines = [f"Endpoint {mac}"]
    if session:
        lines += [
            "",
            "Active session",
            f"  user           {first(session, 'user_name')}",
            f"  ip             {first(session, 'framed_ip_address')}",
            f"  device / port  {first(session, 'network_device_name', 'nas_ip_address')} / {first(session, 'nas_port_id')}",
            f"  authz profile  {first(session, 'selected_azn_profiles')}",
            f"  sgt            {first(session, 'cts_security_group', 'security_group')}",
            f"  posture        {first(session, 'posture_status')}",
        ]
    else:
        lines += ["", "Active session  none (not connected, or session already cleared)"]

    lines += ["", f"Authentication history ({len(records)} records, newest first)"]
    for r in records:
        ok = passed(r)
        lines.append(
            f"  {first(r, 'acs_timestamp', 'acsview_timestamp'):26} {'PASS' if ok else 'FAIL'}  "
            f"user={first(r, 'user_name')}  method={first(r, 'authentication_method')}/{first(r, 'authentication_protocol', 'authen_protocol')}  "
            f"device={first(r, 'network_device_name', 'nas_ip_address')} port={first(r, 'nas_port_id')}"
        )
        if ok:
            lines.append(
                f"{'':30}authz={first(r, 'selected_azn_profiles')}  sgt={first(r, 'cts_security_group', 'security_group')}  "
                f"rule={first(r, 'AuthorizationPolicyMatchedRule')}"
            )
        else:
            reason = first(r, "failure_reason")
            lines.append(f"{'':30}reason: {reason}")
            h = hint(reason)
            if h:
                lines.append(f"{'':30}likely cause: {h}")
    return "\n".join(lines)


def fetch(mnt: str, mac: str, seconds: int, records: int, verify) -> tuple:
    import requests  # lazy: offline mode needs no dependencies

    user = os.environ.get("ISE_USERNAME") or input("ISE username: ")
    pwd = os.environ.get("ISE_PASSWORD") or getpass.getpass("ISE password: ")
    s = requests.Session()
    s.auth = (user, pwd)
    s.headers["Accept"] = "application/xml"
    s.verify = verify
    base = f"https://{mnt}/admin/API/mnt"
    sess = s.get(f"{base}/Session/MACAddress/{mac}", timeout=30)
    sess_xml = sess.text if sess.status_code == 200 else ""
    auth = s.get(f"{base}/AuthStatus/MACAddress/{mac}/{seconds}/{records}/All", timeout=60)
    auth.raise_for_status()
    return sess_xml, auth.text


def normalize_mac(mac: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(h) != 12:
        raise ValueError(f"not a MAC address: {mac}")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).upper()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Explain why an endpoint got its ISE result")
    p.add_argument("mac", help="endpoint MAC in any common format")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--mnt", help="ISE MnT (or PAN) node hostname or IP")
    g.add_argument("--offline", type=Path, help="directory with session.xml and authstatus.xml")
    p.add_argument("--seconds", type=int, default=86400, help=f"history window, max {MAX_SECONDS}")
    p.add_argument("--records", type=int, default=20)
    p.add_argument("--ca-bundle")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (lab only)")
    a = p.parse_args(argv)

    try:
        mac = normalize_mac(a.mac)
        seconds = max(1, min(a.seconds, MAX_SECONDS))
        if a.offline:
            sp, ap = a.offline / "session.xml", a.offline / "authstatus.xml"
            sess_xml = sp.read_text(encoding="utf-8") if sp.exists() else ""
            auth_xml = ap.read_text(encoding="utf-8")
        else:
            verify = False if a.insecure else (a.ca_bundle or True)
            sess_xml, auth_xml = fetch(a.mnt, mac, seconds, a.records, verify)
        session, records = parse_session(sess_xml), parse_authstatus(auth_xml)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(render(mac, session, records))
    return 0 if records and passed(records[0]) else 1


if __name__ == "__main__":
    sys.exit(main())
