#!/usr/bin/env python3
"""
DPAT (Slim) – NTDS + Hashcat potfile → HTML report

This is a slimmed-down variant of DPAT focused on:
- Parsing an NTDS dump (e.g., secretsdump output)
- Ingesting a cracking potfile (hash:password lines)
- Producing a single HTML report (summary + key tables)

It intentionally omits:
- Group membership processing
- Kerberoast / auxiliary reports
- SQLite on-disk options and “speed mode” toggles

Usage examples:
  python dpat_slim.py -n customer.ntds -c hashcat.potfile -p 8
  python dpat_slim.py -n customer.ntds -c hashcat.potfile -p 12 -s
  python dpat_slim.py -n customer.ntds -c hashcat.potfile -p 10 -d "DPAT Report"
  python dpat_slim.py -n customer.ntds -c hashcat.potfile -p 8 -d "DPAT Report" --bh-url "http://127.0.0.1:8080/" --bh-user "admin" --bh-pass "password"

Notes:
- Expects NTDS lines in secretsdump / pwdump-like format:
    DOMAIN\\user:RID:LMHASH:NTHASH:...
  (other lines are skipped)
- Expects potfile lines:
    <hash>:<password>
  where <hash> is typically a 32-hex NT hash.

"""

from __future__ import annotations

import argparse
import csv
import binascii
import html
import json
import logging
import os
import re
import sqlite3
import statistics
import requests
from urllib.parse import urljoin
from dataclasses import dataclass
from pathlib import Path
from shutil import copyfile
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# --------------------------- Logging ---------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("dpat_slim")

class BloodHoundClient:
    """Minimal BloodHound CE API client for cypher enrichment.

    Uses JWT login via /api/v2/login and then runs read-only cypher queries via /api/v2/graphs/cypher.
    """

    def __init__(self, base_url: str, username: str, password: str, *, verify_tls: bool = True, timeout: int = 30):
        self.base_url = base_url.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._token: Optional[str] = None

    def login(self) -> str:
        url = urljoin(self.base_url, "api/v2/login")
        payload = {"login_method": "secret", "username": self.username, "secret": self.password}
        r = requests.post(url, json=payload, timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()
        data = r.json().get("data") or {}
        token = data.get("session_token")
        if not token:
            raise RuntimeError("BloodHound login succeeded but no session_token was returned.")
        self._token = token
        return token

    def run_cypher(self, query: str, *, include_properties: bool = True) -> dict:
        if not self._token:
            self.login()
        url = urljoin(self.base_url, "api/v2/graphs/cypher")
        headers = {"Authorization": f"Bearer {self._token}"}
        payload = {"query": query, "include_properties": bool(include_properties)}
        r = requests.post(url, json=payload, headers=headers, timeout=self.timeout, verify=self.verify_tls)
        r.raise_for_status()
        return r.json()


@dataclass(frozen=True)
class BHNodeMeta:
    name: Optional[str]
    samaccountname: Optional[str]
    enabled: Optional[bool]
    tier_zero: Optional[bool]
    objectid: Optional[str]
    kind: Optional[str]



def _safe_bool(v) -> Optional[bool]:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"true", "t", "1", "yes", "y"}:
            return True
        if s in {"false", "f", "0", "no", "n"}:
            return False
    return None


def fetch_bh_user_metadata(cfg: Config) -> Tuple[Dict[str, BHNodeMeta], Dict[str, int], List[BHNodeMeta]]:
    """Fetch BloodHound CE metadata and build a lookup index.

    This performs two read-only cypher queries:
      1) Tier Zero + enabled targets (user-supplied query pattern), returning :Base nodes.
      2) All users (for enabled state coverage), returning :User nodes.

    The resulting index is keyed by multiple normalised identifiers to maximise match rate:
      - samaccountname (lower)
      - name/label (lower)
      - name prefix before '@' (lower) (for UserPrincipalName-style names)

    NOTE: BloodHound CE often models Tier Zero as either the Tag_Tier_Zero label or a system tag
          such as 'admin_tier_0'. This function follows that approach.
    """
    assert cfg.bh_url and cfg.bh_username and cfg.bh_password

    client = BloodHoundClient(
        cfg.bh_url,
        cfg.bh_username,
        cfg.bh_password,
        verify_tls=cfg.bh_verify_tls,
        timeout=cfg.bh_timeout,
    )

    # Query (1): Tier Zero + enabled targets (Base nodes)
    tier0_query = (
        "MATCH (n:Base) "
        "WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0') "
        "AND n.enabled = true "
        "RETURN n"
    )
    tier0_resp = client.run_cypher(tier0_query, include_properties=True)
    tier0_data = (tier0_resp.get("data") or {})
    tier0_nodes = (tier0_data.get("nodes") or {})

    tier0_objectids: set[str] = set()
    tier0_keys: set[str] = set()

    def _node_to_meta(node: dict, *, default_tier0: Optional[bool] = None) -> BHNodeMeta:
        props = node.get("properties") or {}
        kind = node.get("kind") or (node.get("kinds")[0] if isinstance(node.get("kinds"), list) and node.get("kinds") else None)
        name = props.get("name") or props.get("displayname") or node.get("label")
        sam = props.get("samaccountname")
        enabled = _safe_bool(props.get("enabled"))
        objectid = props.get("objectid") or props.get("object_id") or node.get("objectId") or node.get("objectid") or node.get("objectID")
        # Tier zero from label/tags if present; otherwise fall back to provided default
        tier_zero = default_tier0
        # BloodHound CE response may include 'isTierZero' at the node level
        if "isTierZero" in node:
            tier_zero = _safe_bool(node.get("isTierZero"))
        # Or it may be inferred by Tag_Tier_Zero in kinds or system_tags
        if tier_zero is None:
            kinds = node.get("kinds") or []
            if isinstance(kinds, list) and any(str(k).lower() == "tag_tier_zero" for k in kinds):
                tier_zero = True
        if tier_zero is None:
            st = props.get("system_tags") or ""
            if isinstance(st, str) and "admin_tier_0" in st:
                tier_zero = True

        return BHNodeMeta(
            name=str(name) if name is not None else None,
            samaccountname=str(sam) if sam is not None else None,
            enabled=enabled,
            tier_zero=tier_zero,
            objectid=str(objectid) if objectid is not None else None,
            kind=str(kind) if kind is not None else None,
        )

    for _, node in tier0_nodes.items():
        if not isinstance(node, dict):
            continue
        meta = _node_to_meta(node, default_tier0=True)
        if meta.objectid:
            tier0_objectids.add(meta.objectid)
        if meta.samaccountname:
            tier0_keys.add(meta.samaccountname.lower())
        if meta.name:
            tier0_keys.add(meta.name.lower())
            if "@" in meta.name:
                tier0_keys.add(meta.name.split("@", 1)[0].lower())

    # Query (2): all users (for enabled coverage)
    users_resp = client.run_cypher("MATCH (u:User) RETURN u", include_properties=True)

    # Query (3): enabled kerberoastable users (User nodes with SPNs)
    kerb_query = (
        "MATCH (u:User) "
        "WHERE u.hasspn=true "
        "AND u.enabled = true "
        "AND NOT u.objectid ENDS WITH '-502' "
        "AND NOT COALESCE(u.gmsa, false) = true "
        "AND NOT COALESCE(u.msa, false) = true "
        "RETURN u"
    )
    kerb_resp = client.run_cypher(kerb_query, include_properties=True)
    kerb_data = (kerb_resp.get("data") or {})
    kerb_nodes = (kerb_data.get("nodes") or {})

    users_data = (users_resp.get("data") or {})
    users_nodes = (users_data.get("nodes") or {})

    meta_by_key: Dict[str, BHNodeMeta] = {}

    kerberoastable_enabled: List[BHNodeMeta] = []

    total_nodes = 0
    total_users = 0
    total_tier0_enabled = len(tier0_nodes)

    def _index(meta: BHNodeMeta) -> None:
        keys = set()
        if meta.samaccountname:
            keys.add(meta.samaccountname.lower())
        if meta.name:
            keys.add(meta.name.lower())
            if "@" in meta.name:
                keys.add(meta.name.split("@", 1)[0].lower())
        if meta.objectid:
            keys.add(meta.objectid.lower())

        for k in keys:
            # Prefer entries with more complete information
            prev = meta_by_key.get(k)
            if prev is None:
                meta_by_key[k] = meta
            else:
                # Merge tier_zero/enabled if missing
                tier_zero = prev.tier_zero if prev.tier_zero is not None else meta.tier_zero
                enabled = prev.enabled if prev.enabled is not None else meta.enabled
                name = prev.name or meta.name
                sam = prev.samaccountname or meta.samaccountname
                objectid = prev.objectid or meta.objectid
                kind = prev.kind or meta.kind
                meta_by_key[k] = BHNodeMeta(name=name, samaccountname=sam, enabled=enabled, tier_zero=tier_zero, objectid=objectid, kind=kind)

    # Index tier0-enabled nodes first (ensures tier_zero flag is set on those entries)
    for _, node in tier0_nodes.items():
        if not isinstance(node, dict):
            continue
        meta = _node_to_meta(node, default_tier0=True)
        # Query filters enabled=true, but keep explicit
        meta = BHNodeMeta(
            name=meta.name,
            samaccountname=meta.samaccountname,
            enabled=True if meta.enabled is None else meta.enabled,
            tier_zero=True,
            objectid=meta.objectid,
            kind=meta.kind,
        )
        _index(meta)

    # Index user nodes (fill in enabled for non-tier0 users)
    for _, node in users_nodes.items():
        total_nodes += 1
        if not isinstance(node, dict):
            continue
        kind = node.get("kind")
        if kind and str(kind).lower() != "user":
            continue
        total_users += 1
        meta = _node_to_meta(node, default_tier0=None)

        # Mark as tier zero if it appears in tier0 keys/objectids
        tz = meta.tier_zero
        if tz is None:
            if meta.objectid and meta.objectid in tier0_objectids:
                tz = True
            elif meta.samaccountname and meta.samaccountname.lower() in tier0_keys:
                tz = True
            elif meta.name and meta.name.lower() in tier0_keys:
                tz = True

        meta = BHNodeMeta(
            name=meta.name,
            samaccountname=meta.samaccountname,
            enabled=meta.enabled,
            tier_zero=tz,
            objectid=meta.objectid,
            kind=meta.kind,
        )
        _index(meta)

    # Collect kerberoastable enabled users (for reporting table)
    for _, node in kerb_nodes.items():
        if not isinstance(node, dict):
            continue
        kind = node.get("kind")
        if kind and str(kind).lower() != "user":
            continue

        meta = _node_to_meta(node, default_tier0=None)

        # Derive tier zero using tier0 objectids/keys collected earlier
        tz = meta.tier_zero
        if tz is None:
            if meta.objectid and meta.objectid in tier0_objectids:
                tz = True
            elif meta.samaccountname and meta.samaccountname.lower() in tier0_keys:
                tz = True
            elif meta.name and meta.name.lower() in tier0_keys:
                tz = True

        meta = BHNodeMeta(
            name=meta.name,
            samaccountname=meta.samaccountname,
            enabled=True if meta.enabled is None else meta.enabled,
            tier_zero=tz,
            objectid=meta.objectid,
            kind=meta.kind or "User",
        )

        kerberoastable_enabled.append(meta)



    stats = {
        "bh_total_nodes": total_nodes,
        "bh_total_users": total_users,
        "bh_total_tier0_enabled": total_tier0_enabled,
        "bh_index_keys": len(meta_by_key),
        "bh_total_kerberoastable_enabled": len(kerberoastable_enabled),
    }
    return meta_by_key, stats, kerberoastable_enabled


# --------------------------- Config ---------------------------

@dataclass
class Config:
    ntds_file: str
    potfile: str
    min_password_length: int
    output_file: str = "_DomainPasswordAuditReport.html"
    report_directory: str = "DPAT Report"
    sanitize_output: bool = False
    include_machine_accounts: bool = False
    include_krbtgt: bool = False
    css_path: Optional[str] = None
    no_prompt: bool = True  # kept for parity; slim version does not auto-open

    # Optional BloodHound CE enrichment (enabled/tier zero)
    bh_url: Optional[str] = None
    bh_username: Optional[str] = None
    bh_password: Optional[str] = None
    bh_verify_tls: bool = True
    bh_timeout: int = 30



# --------------------------- Helpers ---------------------------

def calculate_percentage(part: int, whole: int) -> float:
    try:
        return round((part / whole) * 100, 2)
    except ZeroDivisionError:
        return 0.0


class DataSanitizer:
    @staticmethod
    def sanitize_value(value: str, enabled: bool) -> str:
        if not enabled or value is None:
            return value
        s = str(value)
        if not s:
            return s
        if len(s) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", s):
            return s[:4] + "*" * 24 + s[-4:]
        if len(s) <= 2:
            return "*" * len(s)
        return s[0] + "*" * (len(s) - 2) + s[-1]

    @staticmethod
    def sanitize_row(row: Tuple, password_indices: Sequence[int], hash_indices: Sequence[int], enabled: bool) -> Tuple:
        if not enabled:
            return row
        out = list(row)
        for idx in password_indices:
            if 0 <= idx < len(out) and out[idx] is not None:
                out[idx] = DataSanitizer.sanitize_value(str(out[idx]), enabled=True)
        for idx in hash_indices:
            if 0 <= idx < len(out) and out[idx] is not None:
                out[idx] = DataSanitizer.sanitize_value(str(out[idx]), enabled=True)
        return tuple(out)



# --------------------------- NTLM hashing (MD4 of UTF-16LE) ---------------------------
# Minimal pure-Python MD4 implementation (sufficient for NTLM hashing).

def _lrot(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def _md4(message: bytes) -> bytes:
    # Based on RFC 1320.
    msg = bytearray(message)
    orig_len_bits = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0)
    msg += orig_len_bits.to_bytes(8, "little")

    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z

    def R1(a, b, c, d, k, s, X): return _lrot((a + F(b, c, d) + X[k]) & 0xFFFFFFFF, s)
    def R2(a, b, c, d, k, s, X): return _lrot((a + G(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
    def R3(a, b, c, d, k, s, X): return _lrot((a + H(b, c, d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    for offset in range(0, len(msg), 64):
        block = msg[offset:offset+64]
        X = [int.from_bytes(block[i:i+4], "little") for i in range(0, 64, 4)]
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        A = R1(A, B, C, D, 0, 3, X);  D = R1(D, A, B, C, 1, 7, X);  C = R1(C, D, A, B, 2, 11, X); B = R1(B, C, D, A, 3, 19, X)
        A = R1(A, B, C, D, 4, 3, X);  D = R1(D, A, B, C, 5, 7, X);  C = R1(C, D, A, B, 6, 11, X); B = R1(B, C, D, A, 7, 19, X)
        A = R1(A, B, C, D, 8, 3, X);  D = R1(D, A, B, C, 9, 7, X);  C = R1(C, D, A, B, 10, 11, X);B = R1(B, C, D, A, 11, 19, X)
        A = R1(A, B, C, D, 12, 3, X); D = R1(D, A, B, C, 13, 7, X); C = R1(C, D, A, B, 14, 11, X);B = R1(B, C, D, A, 15, 19, X)

        # Round 2
        A = R2(A, B, C, D, 0, 3, X);  D = R2(D, A, B, C, 4, 5, X);  C = R2(C, D, A, B, 8, 9, X);  B = R2(B, C, D, A, 12, 13, X)
        A = R2(A, B, C, D, 1, 3, X);  D = R2(D, A, B, C, 5, 5, X);  C = R2(C, D, A, B, 9, 9, X);  B = R2(B, C, D, A, 13, 13, X)
        A = R2(A, B, C, D, 2, 3, X);  D = R2(D, A, B, C, 6, 5, X);  C = R2(C, D, A, B, 10, 9, X); B = R2(B, C, D, A, 14, 13, X)
        A = R2(A, B, C, D, 3, 3, X);  D = R2(D, A, B, C, 7, 5, X);  C = R2(C, D, A, B, 11, 9, X); B = R2(B, C, D, A, 15, 13, X)

        # Round 3
        A = R3(A, B, C, D, 0, 3, X);  D = R3(D, A, B, C, 8, 9, X);  C = R3(C, D, A, B, 4, 11, X); B = R3(B, C, D, A, 12, 15, X)
        A = R3(A, B, C, D, 2, 3, X);  D = R3(D, A, B, C, 10, 9, X); C = R3(C, D, A, B, 6, 11, X); B = R3(B, C, D, A, 14, 15, X)
        A = R3(A, B, C, D, 1, 3, X);  D = R3(D, A, B, C, 9, 9, X);  C = R3(C, D, A, B, 5, 11, X); B = R3(B, C, D, A, 13, 15, X)
        A = R3(A, B, C, D, 3, 3, X);  D = R3(D, A, B, C, 11, 9, X); C = R3(C, D, A, B, 7, 11, X); B = R3(B, C, D, A, 15, 15, X)

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return (A.to_bytes(4, "little") +
            B.to_bytes(4, "little") +
            C.to_bytes(4, "little") +
            D.to_bytes(4, "little"))

def ntlm_hash(s: str) -> str:
    # NTLM = MD4(UTF-16LE(password))
    if s is None:
        return ""
    return _md4(s.encode("utf-16le", errors="surrogatepass")).hex()

# --------------------------- Parsing ---------------------------

NTDS_LINE_RE = re.compile(
    r"^(?P<user>[^:]+):(?P<rid>\d+):(?P<lm>[0-9A-Fa-f\*]{32}):(?P<nt>[0-9A-Fa-f\*]{32}):",
    re.IGNORECASE,
)

def parse_ntds_line(line: str) -> Optional[Tuple[str, str, str]]:
    """Return (username_full, lm_hash, nt_hash) or None."""
    m = NTDS_LINE_RE.match(line.strip())
    if not m:
        return None
    user_full = m.group("user")
    lm = m.group("lm").lower()
    nt = m.group("nt").lower()
    return (user_full, lm, nt)


def decode_hex_password(pw: str) -> str:
    """Decode hashcat $HEX[...] if present."""
    m = re.match(r'^\$HEX\[([0-9A-Fa-f]+)\]$', pw, flags=re.IGNORECASE)
    if not m:
        return pw
    try:
        return binascii.unhexlify(m.group(1)).decode("utf-8", errors="replace")
    except Exception:
        try:
            # Some potfiles use raw bytes that aren't valid UTF-8
            return "".join(chr(b) for b in binascii.unhexlify(m.group(1)))
        except Exception:
            return pw


def iter_potfile(path: str) -> Iterable[Tuple[str, str]]:
    """Yield (hash, password) pairs. Supports 'hash:password' where hash is 32 hex."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\\n")
            if ":" not in line:
                continue
            h, pw = line.split(":", 1)
            h = h.strip()
            pw = pw.strip()
            # John the Ripper can prefix $NT$; strip common prefixes
            if h.startswith("$NT$"):
                h = h[4:]
            if len(h) == 32 and re.fullmatch(r"[0-9A-Fa-f]{32}", h):
                yield (h.lower(), decode_hex_password(pw))


# --------------------------- DB (in-memory) ---------------------------

class DB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.text_factory = str
        self.cur = self.conn.cursor()
        self._create()

    def _create(self) -> None:
        self.cur.execute("""
            CREATE TABLE accounts (
                username_full TEXT COLLATE NOCASE,
                username TEXT COLLATE NOCASE,
                lm_hash TEXT,
                nt_hash TEXT,
                password TEXT,
                only_lm_cracked INTEGER DEFAULT 0,
                username_nt_match INTEGER DEFAULT 0,
                username_nt_match_variant TEXT
            )
        """)
        self.cur.execute("CREATE INDEX idx_nt ON accounts (nt_hash)")
        self.cur.execute("CREATE INDEX idx_user ON accounts (username)")

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()


# --------------------------- Processing ---------------------------

BLANK_LM = "aad3b435b51404eeaad3b435b51404ee"
STAR32 = "*" * 32

def should_include(username: str, cfg: Config) -> bool:
    if not cfg.include_machine_accounts and username.endswith("$"):
        return False
    if not cfg.include_krbtgt and username.lower() == "krbtgt":
        return False
    return True



def compute_username_hash_matches(cfg: Config, db: DB) -> None:
    """Flag accounts where NT hash matches the NTLM hash of the username.

    Detects 'username as password' even when the password is not cracked by hashing common
    username variants and comparing to the stored NT hash.
    """
    db.cur.execute("SELECT rowid, username, nt_hash FROM accounts")
    rows = db.cur.fetchall()
    updated = 0
    for rowid, username, nt_hash_val in rows:
        if not username or not nt_hash_val:
            continue

        candidates = [
            ("username", username),
            ("lower", username.lower()),
            ("upper", username.upper()),
        ]

        matched_variant = None
        for label, cand in candidates:
            h = ntlm_hash(cand)
            if h and h.lower() == str(nt_hash_val).lower():
                matched_variant = label
                break

        if matched_variant:
            db.cur.execute(
                "UPDATE accounts SET username_nt_match = 1, username_nt_match_variant = ? WHERE rowid = ?",
                (matched_variant, rowid),
            )
            updated += db.cur.rowcount

    logger.info("Username-as-password (hash match) flags set for %d accounts", updated)

def load_ntds(cfg: Config, db: DB) -> None:
    logger.info("Reading NTDS file: %s", cfg.ntds_file)
    read = 0
    kept = 0

    with open(cfg.ntds_file, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            parsed = parse_ntds_line(raw)
            if not parsed:
                continue
            read += 1
            username_full, lm, nt = parsed
            username = username_full.split("\\\\")[-1].split("@")[0]  # safe fallback
            if not should_include(username, cfg):
                continue
            # Skip empty NT hashes (rare, but keep consistent)
            if nt == STAR32:
                continue
            db.cur.execute(
                "INSERT INTO accounts (username_full, username, lm_hash, nt_hash) VALUES (?, ?, ?, ?)",
                (username_full, username, lm, nt),
            )
            kept += 1

    logger.info("Parsed %d accounts, kept %d after filtering", read, kept)


def apply_potfile(cfg: Config, db: DB) -> None:
    logger.info("Reading potfile: %s", cfg.potfile)
    updated = 0
    for nt_hash, password in iter_potfile(cfg.potfile):
        db.cur.execute("UPDATE accounts SET password = ? WHERE nt_hash = ?", (password, nt_hash))
        updated += db.cur.rowcount
    logger.info("Mapped %d cracked passwords to accounts (rows updated may include duplicates)", updated)


# --------------------------- HTML report ---------------------------


def _safe_filename(name: str) -> str:
    # Create filesystem-safe, stable filenames for table exports
    name = (name or "").strip().lower()
    name = re.sub(r"[^a-z0-9._-]+", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    return name or "table"

def export_table_csv(report_dir: str, folder_name: str, table_title: str, headers: Sequence[str], rows: Sequence[Sequence]) -> Path:
    out_dir = Path(report_dir) / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)
    fname = _safe_filename(table_title) + ".csv"
    out_path = out_dir / fname

    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(list(headers))
        for r in rows:
            w.writerow([("" if v is None else str(v)) for v in r])
    return out_path


class HTMLReport:
    def __init__(self, report_dir: str, output_file: str):
        self.report_dir = Path(report_dir)
        self.output_file = output_file
        self.body: List[str] = []
        self.charts: List[dict] = []

    def add(self, s: str) -> None:
        self.body.append(s)
        self.body.append("<div class='section-space'></div>")

    def add_table(
        self,
        rows: Sequence[Sequence],
        headers: Sequence[str],
        caption: Optional[str] = None,
        cols_to_not_escape: Optional[Sequence[int]] = None,
    ) -> None:
        cols_to_not_escape = set(cols_to_not_escape or [])
        parts = ["<div class='table-wrap'>", "<table class='table table-striped table-hover datatable'>"]
        if caption:
            parts.append(f"<caption>{html.escape(caption)}</caption>")
        parts.append("<thead><tr>")
        for h in headers:
            parts.append(f"<th>{html.escape(str(h))}</th>")
        parts.append("</tr></thead><tbody>")

        for row in rows:
            parts.append("<tr>")
            for idx, cell in enumerate(row):
                cell_s = "" if cell is None else str(cell)
                if idx not in cols_to_not_escape:
                    cell_s = html.escape(cell_s)
                parts.append(f"<td>{cell_s}</td>")
            parts.append("</tr>")

        parts.append("</tbody></table></div>")
        self.add("".join(parts))

    def add_chart(self, chart_id: str, chart_type: str, data: dict, options: Optional[dict] = None) -> None:
        options = options or {}
        width = "50%" if chart_type == "pie" else "100%"
        chart_html = f"""
<div class='table-wrap' style='text-align: center;'>
  <div class='chart-container' style='position: relative; width: {width}; margin: 20px auto; display: inline-block;'>
    <canvas id='{chart_id}'></canvas>
  </div>
</div>
"""
        self.add(chart_html)
        self.charts.append(
            {
                "id": chart_id,
                "type": chart_type,
                "data": json.dumps(data),
                "options": json.dumps(options),
            }
        )

    def _html_doc(self) -> str:
        charts_json = json.dumps(self.charts)
        return f"""<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>DPAT Report</title>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
<link href='https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css' rel='stylesheet'>
<link rel='stylesheet' href='report.css'>
</head>
<body>
<script>
(function() {{
  const savedTheme = localStorage.getItem('theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const isDark = (savedTheme !== null) ? (savedTheme === 'dark') : prefersDark;
  document.documentElement.classList.add(isDark ? 'dark-theme' : 'light-theme');
}})();
</script>

<nav class='navbar navbar-expand-lg navbar-dark bg-primary fixed-top'>
  <div class='container-fluid'>
    <a class='navbar-brand fw-bold' href='#'>DPAT Report</a>
    <div class='collapse navbar-collapse' id='navbarNav'>
      <ul class='navbar-nav ms-auto'>
        <li class='nav-item'>
          <button id='theme-toggle' class='btn btn-outline-light btn-sm' aria-label='Toggle dark mode'>
            <span class='theme-toggle-icon'>🌙</span>
          </button>
        </li>
      </ul>
    </div>
  </div>
</nav>

<div class='main-content'>
{''.join(self.body)}
</div>

<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>
<script src='https://code.jquery.com/jquery-3.7.0.min.js'></script>
<script src='https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js'></script>
<script src='https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js'></script>
<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>

<script>
document.addEventListener('DOMContentLoaded', function() {{
  const themeToggle = document.getElementById('theme-toggle');
  const themeIcon = themeToggle.querySelector('.theme-toggle-icon');

  function setIcon() {{
    const isDark = document.documentElement.classList.contains('dark-theme');
    themeIcon.textContent = isDark ? '☀️' : '🌙';
  }}
  setIcon();

  function initializeDataTables() {{
    $('.datatable').each(function() {{
      const table = $(this);
      if ($.fn.DataTable.isDataTable(table)) {{
        table.DataTable().destroy();
      }}
      table.DataTable({{
        responsive: true,
        order: [],
        pageLength: 25,
        lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, 'All']],
      }});
    }});
  }}

  themeToggle.addEventListener('click', function() {{
    const isDark = document.documentElement.classList.contains('dark-theme');
    document.documentElement.classList.toggle('dark-theme', !isDark);
    document.documentElement.classList.toggle('light-theme', isDark);
    localStorage.setItem('theme', isDark ? 'light' : 'dark');
    setIcon();
    setTimeout(initializeDataTables, 100);
  }});

  initializeDataTables();

  const chartsData = {charts_json};
  if (typeof Chart !== 'undefined') {{
    chartsData.forEach(function(cfg) {{
      const canvas = document.getElementById(cfg.id);
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      new Chart(ctx, {{
        type: cfg.type,
        data: JSON.parse(cfg.data),
        options: JSON.parse(cfg.options),
      }});
    }});
  }}
}});
</script>
</body>
</html>
"""

    def write(self, css_path: Optional[str]) -> Path:
        self.report_dir.mkdir(parents=True, exist_ok=True)

        # Copy CSS
        dest_css = self.report_dir / "report.css"
        if css_path:
            css_src = Path(css_path)
            if css_src.exists():
                copyfile(css_src, dest_css)
        else:
            # Try alongside the script
            css_src = Path(__file__).with_name("report.css")
            if css_src.exists():
                copyfile(css_src, dest_css)

        out_path = self.report_dir / self.output_file
        out_path.write_text(self._html_doc(), encoding="utf-8")
        logger.info("Report written: %s", out_path)
        return out_path


# --------------------------- Analysis queries ---------------------------

def build_report(cfg: Config, db: DB) -> Path:
    sanitizer = DataSanitizer()

    csv_folder = "tables_csv"

    def add_table_and_export(
        rows: Sequence[Sequence],
        headers: Sequence[str],
        caption: Optional[str] = None,
        cols_to_not_escape: Optional[Sequence[int]] = None,
    ) -> None:
        # Add to HTML
        HTMLReport.add_table(r, rows, headers, caption=caption, cols_to_not_escape=cols_to_not_escape)
        # Export to CSV (mirrors report sanitization by exporting the same rows)
        try:
            export_table_csv(cfg.report_directory, csv_folder, caption or "table", headers, rows)
        except Exception as e:
            logger.warning("Failed to export table '%s' to CSV: %s", caption or "table", e)

    # Optional BloodHound CE enrichment (enabled/tier zero)
    bh_meta: Optional[Dict[str, BHNodeMeta]] = None
    bh_stats: Dict[str, int] = {}
    bh_kerb: List[BHNodeMeta] = []
    if cfg.bh_url or cfg.bh_username or cfg.bh_password:
        if not (cfg.bh_url and cfg.bh_username and cfg.bh_password):
            logger.warning("BloodHound enrichment requested but --bh-url/--bh-user/--bh-pass are not all set; skipping.")
        else:
            try:
                bh_meta, bh_stats, bh_kerb = fetch_bh_user_metadata(cfg)
                logger.info("BloodHound enrichment loaded: %s users, %s tier0-enabled objects, %s index keys", bh_stats.get("bh_total_users"), bh_stats.get("bh_total_tier0_enabled"), bh_stats.get("bh_index_keys"))
            except Exception as e:
                logger.warning("Failed to load BloodHound enrichment; continuing without it. Error: %s", e)

    def bh_lookup(username_full: str, username: str) -> Optional[BHNodeMeta]:
        if not bh_meta:
            return None
        keys = set()
        if username:
            keys.add(username.lower())
        if username_full:
            keys.add(username_full.lower())
            if "\\" in username_full:
                dom, u = username_full.split("\\", 1)
                keys.add(u.lower())
                keys.add(f"{u}@{dom}".lower())
        for k in keys:
            if k in bh_meta:
                return bh_meta[k]
        return None

    # Totals
    db.cur.execute("SELECT COUNT(*) FROM accounts")
    total = db.cur.fetchone()[0]

    db.cur.execute("SELECT COUNT(*) FROM accounts WHERE password IS NOT NULL")
    cracked = db.cur.fetchone()[0]

    db.cur.execute("SELECT COUNT(DISTINCT nt_hash) FROM accounts")
    unique_hashes = db.cur.fetchone()[0]

    duplicates = total - unique_hashes

    # Policy violations (among cracked)
    db.cur.execute(
        "SELECT COUNT(*) FROM accounts WHERE password IS NOT NULL AND LENGTH(password) < ?",
        (cfg.min_password_length,),
    )
    policy_violations = db.cur.fetchone()[0]

    # Username == password (among cracked)
    db.cur.execute(
        "SELECT COUNT(*) FROM accounts WHERE password IS NOT NULL AND LOWER(username) = LOWER(password)"
    )
    user_eq_pw = db.cur.fetchone()[0]

    # Username-as-password via NTLM hash match (independent of cracked set)
    db.cur.execute("SELECT COUNT(*) FROM accounts WHERE username_nt_match = 1")
    user_eq_pw_hash = db.cur.fetchone()[0]

    # Non-blank LM hashes
    db.cur.execute(
        "SELECT COUNT(*) FROM accounts WHERE lm_hash IS NOT NULL AND lm_hash != ?",
        (BLANK_LM,),
    )
    lm_nonblank = db.cur.fetchone()[0]

    # Build report
    r = HTMLReport(cfg.report_directory, cfg.output_file)

    r.add("<h2>Domain Password Audit Report</h2>")
    r.add(
        "<p class='text-left'>This report summarises password exposure based on the supplied NTDS extract and cracking potfile.</p>"
    )

    # Summary table
    summary_rows = [
        ("Accounts Analysed", total, None),
        ("Unique NT Hashes", unique_hashes, f"{calculate_percentage(unique_hashes, total)}%"),
        ("Duplicate NT Hashes", duplicates, f"{calculate_percentage(duplicates, total)}%"),
        ("Cracked Passwords", cracked, f"{calculate_percentage(cracked, total)}%"),
        (f"Passwords Below Policy Minimum (< {cfg.min_password_length})", policy_violations,
         f"{calculate_percentage(policy_violations, cracked) if cracked else 0}% of cracked"),
        ("Accounts Using Username as Password (cracked set)", user_eq_pw,
         f"{calculate_percentage(user_eq_pw, cracked) if cracked else 0}% of cracked"),
        ("Accounts Using Username as Password (hash match)", user_eq_pw_hash, f"{calculate_percentage(user_eq_pw_hash, total)}%"),
        ("LM Hash Present (Non-blank)", lm_nonblank, f"{calculate_percentage(lm_nonblank, total)}%"),
    ]
    if bh_meta:
        db.cur.execute("SELECT username_full, username, password IS NOT NULL AS cracked FROM accounts")
        rows = db.cur.fetchall()
        matched = enabled = disabled = hv = 0
        cracked_matched = cracked_enabled = cracked_hv = cracked_enabled_hv = 0
        for ufull, uname, is_cracked in rows:
            meta = bh_lookup(ufull or "", uname or "")
            if not meta:
                continue
            matched += 1
            if meta.enabled is True:
                enabled += 1
            elif meta.enabled is False:
                disabled += 1
            if meta.tier_zero is True:
                hv += 1
            if is_cracked:
                cracked_matched += 1
                if meta.enabled is True:
                    cracked_enabled += 1
                if meta.tier_zero is True:
                    cracked_hv += 1
                if meta.enabled is True and meta.tier_zero is True:
                    cracked_enabled_hv += 1
        summary_rows.extend([
            ("BloodHound Users Matched", matched, f"{calculate_percentage(matched, total)}% of accounts"),
            ("BloodHound Enabled (Matched)", enabled, f"{calculate_percentage(enabled, matched) if matched else 0}% of matched"),
            ("BloodHound Disabled (Matched)", disabled, f"{calculate_percentage(disabled, matched) if matched else 0}% of matched"),
            ("BloodHound Tier Zero (Matched)", hv, f"{calculate_percentage(hv, matched) if matched else 0}% of matched"),
            ("Cracked & Enabled (Matched)", cracked_enabled, f"{calculate_percentage(cracked_enabled, cracked_matched) if cracked_matched else 0}% of matched cracked"),
            ("Cracked & Tier Zero (Matched)", cracked_hv, f"{calculate_percentage(cracked_hv, cracked_matched) if cracked_matched else 0}% of matched cracked"),
            ("Cracked & Enabled & Tier Zero (Matched)", cracked_enabled_hv, f"{calculate_percentage(cracked_enabled_hv, cracked_matched) if cracked_matched else 0}% of matched cracked"),
        ])
    add_table_and_export(summary_rows, ["Metric", "Count", "Percentage"], caption="Summary")

    # Chart: cracked vs uncracked
    r.add_chart(
        "chart_cracked",
        "pie",
        data={
            "labels": ["Cracked", "Not cracked"],
            "datasets": [{"data": [cracked, max(total - cracked, 0)]}],
        },
        options={
            "plugins": {
                "legend": {"position": "bottom"},
                "title": {"display": True, "text": "Cracked Coverage"},
            }
        },
    )


    # Password length statistics (cracked set)
    db.cur.execute("SELECT LENGTH(password) AS plen FROM accounts WHERE password IS NOT NULL")
    lens = [r0[0] for r0 in db.cur.fetchall() if r0 and r0[0] is not None]
    if lens:
        avg_len = round(sum(lens) / len(lens), 2)
        min_len = min(lens)
        max_len = max(lens)
        median_len = float(statistics.median(lens))
    else:
        avg_len = 0.0
        min_len = 0
        max_len = 0
        median_len = 0.0

    add_table_and_export(
        [("Min", min_len), ("Max", max_len), ("Average", avg_len), ("Median", median_len)],
        ["Statistic", "Value"],
        caption="Password Length Statistics (Cracked Set)",
    )

    # Table: counts by exact password length (cracked set)
    db.cur.execute(
        """
        SELECT LENGTH(password) AS length, COUNT(*) AS count
        FROM accounts
        WHERE password IS NOT NULL
        GROUP BY LENGTH(password)
        ORDER BY LENGTH(password) ASC
        """
    )
    len_rows = db.cur.fetchall()
    len_rows = [(l, c, f"{calculate_percentage(c, cracked) if cracked else 0}%") for (l, c) in len_rows]
    add_table_and_export(
        len_rows,
        ["Password Length", "Count", "Percentage of Cracked"],
        caption="Password Length Counts (Cracked Set)",
    )

    # Table: cracked accounts (top 200 for practicality)
    db.cur.execute(
        """
        SELECT username_full, username, password, LENGTH(password) AS plen, nt_hash
        FROM accounts
        WHERE password IS NOT NULL
        ORDER BY plen DESC, username_full
        LIMIT 200
        """
    )
    cracked_rows_raw = db.cur.fetchall()

    cracked_rows = []
    for username_full, username, password, plen, nt_hash in cracked_rows_raw:
        meta = bh_lookup(username_full or "", username or "")
        enabled_str = "Unknown"
        hv_str = "Unknown"
        if meta:
            if meta.enabled is True:
                enabled_str = "Yes"
            elif meta.enabled is False:
                enabled_str = "No"
            if meta.tier_zero is True:
                hv_str = "Yes"
            elif meta.tier_zero is False:
                hv_str = "No"

        row = (username_full, password, plen, nt_hash, enabled_str, hv_str)
        row = sanitizer.sanitize_row(row, [1], [3], cfg.sanitize_output)
        cracked_rows.append(row)

    add_table_and_export(
        cracked_rows,
        ["Username", "Password", "Password Length", "NT Hash", "Enabled (BH)", "Tier Zero (BH)"],
        caption="Cracked Passwords (by length)",
        cols_to_not_escape=[],
    )
    # Additional requested tables (derived from the same NTDS + potfile dataset)

    # Top reused passwords (password only + occurrences)
    db.cur.execute(
        """
        SELECT password, COUNT(*) AS c
        FROM accounts
        WHERE password IS NOT NULL
        GROUP BY password
        HAVING c > 1
        ORDER BY c DESC, LENGTH(password) DESC, password ASC
        LIMIT 50
        """
    )
    reused_pw_rows = db.cur.fetchall()
    reused_pw_rows = [sanitizer.sanitize_row(row, [0], [], cfg.sanitize_output) for row in reused_pw_rows]
    if reused_pw_rows:
        add_table_and_export(
            reused_pw_rows,
            ["Password", "Occurrences"],
            caption="Top Reused Passwords (Count Only)",
        )
    else:
        r.add("<p class='text-left'><strong>Top Reused Passwords</strong>: No reused passwords were identified in the cracked set.</p>")

    # LM Hash present (non-blank)
    db.cur.execute(
        """
        SELECT username_full, lm_hash, nt_hash
        FROM accounts
        WHERE lm_hash IS NOT NULL
          AND lm_hash != ?
          AND lm_hash != ?
        ORDER BY username_full
        """,
        (BLANK_LM, STAR32),
    )
    lm_rows = db.cur.fetchall()
    lm_rows = [sanitizer.sanitize_row(row, [], [1, 2], cfg.sanitize_output) for row in lm_rows]
    if lm_rows:
        add_table_and_export(
            lm_rows,
            ["Username", "LM Hash", "NT Hash"],
            caption="LM Hash Present (Non-blank)",
        )
    else:
        r.add("<p class='text-left'><strong>LM Hash Present</strong>: None detected (or LM storage is disabled/blank for all accounts in scope).</p>")

    # BloodHound-derived tables (only when BH enrichment is available)
    if bh_meta:
        db.cur.execute(
            """
            SELECT username_full, username, password, LENGTH(password) AS plen, nt_hash
            FROM accounts
            ORDER BY username_full
            """
        )
        all_rows = db.cur.fetchall()

        bh_matched = []
        bh_enabled = []
        bh_disabled = []
        bh_t0 = []

        cracked_enabled = []
        cracked_t0 = []
        cracked_enabled_t0 = []

        for username_full, username, password, plen, nt_hash in all_rows:
            meta = bh_lookup(username_full or "", username or "")
            if not meta:
                continue

            enabled_str = "Unknown"
            if meta.enabled is True:
                enabled_str = "Yes"
            elif meta.enabled is False:
                enabled_str = "No"

            t0_str = "Unknown"
            if meta.tier_zero is True:
                t0_str = "Yes"
            elif meta.tier_zero is False:
                t0_str = "No"

            cracked_str = "Yes" if password else "No"

            base_row = (
                username_full,
                meta.kind or "",
                meta.objectid or "",
                enabled_str,
                t0_str,
                cracked_str,
            )
            base_row = sanitizer.sanitize_row(base_row, [], [], cfg.sanitize_output)
            bh_matched.append(base_row)

            if meta.enabled is True:
                bh_enabled.append(base_row)
            elif meta.enabled is False:
                bh_disabled.append(base_row)

            if meta.tier_zero is True:
                bh_t0.append(base_row)

            # Intersections where the account is cracked
            if password:
                inter_row = (
                    username_full,
                    password,
                    plen,
                    nt_hash,
                    meta.kind or "",
                    meta.objectid or "",
                )
                inter_row = sanitizer.sanitize_row(inter_row, [1], [3], cfg.sanitize_output)

                if meta.enabled is True:
                    cracked_enabled.append(inter_row)
                if meta.tier_zero is True:
                    cracked_t0.append(inter_row)
                if meta.enabled is True and meta.tier_zero is True:
                    cracked_enabled_t0.append(inter_row)

        # BH matched
        if bh_matched:
            add_table_and_export(
                bh_matched[:500],
                ["Username", "Kind (BH)", "ObjectId (BH)", "Enabled (BH)", "Tier Zero (BH)", "Cracked (DPAT)"],
                caption="BloodHound Users Matched",
            )
        else:
            r.add("<p class='text-left'><strong>BloodHound Users Matched</strong>: No matches were identified.</p>")

        # BH enabled matched
        if bh_enabled:
            add_table_and_export(
                bh_enabled[:500],
                ["Username", "Kind (BH)", "ObjectId (BH)", "Enabled (BH)", "Tier Zero (BH)", "Cracked (DPAT)"],
                caption="BloodHound Enabled (Matched)",
            )
        else:
            r.add("<p class='text-left'><strong>BloodHound Enabled (Matched)</strong>: No enabled matched objects were identified.</p>")

        # BH disabled matched
        if bh_disabled:
            add_table_and_export(
                bh_disabled[:500],
                ["Username", "Kind (BH)", "ObjectId (BH)", "Enabled (BH)", "Tier Zero (BH)", "Cracked (DPAT)"],
                caption="BloodHound Disabled (Matched)",
            )
        else:
            r.add("<p class='text-left'><strong>BloodHound Disabled (Matched)</strong>: No disabled matched objects were identified.</p>")

        # BH tier zero matched
        if bh_t0:
            add_table_and_export(
                bh_t0[:500],
                ["Username", "Kind (BH)", "ObjectId (BH)", "Enabled (BH)", "Tier Zero (BH)", "Cracked (DPAT)"],
                caption="BloodHound Tier Zero (Matched)",
            )
        else:
            r.add("<p class='text-left'><strong>BloodHound Tier Zero (Matched)</strong>: No Tier Zero matched objects were identified.</p>")


        # Enabled kerberoastable users (BloodHound)
        if bh_kerb:
            # Build a lookup index for accounts so we can annotate cracked status
            db.cur.execute("SELECT username_full, username, password, nt_hash FROM accounts")
            acct_rows = db.cur.fetchall()
            acct_by_key: Dict[str, Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]] = {}

            def _acct_index(username_full: Optional[str], username: Optional[str], password: Optional[str], nt_hash: Optional[str]) -> None:
                keys = set()
                if username:
                    keys.add(username.lower())
                if username_full:
                    ufl = username_full.lower()
                    keys.add(ufl)
                    if "\\" in ufl:
                        dom, u = ufl.split("\\", 1)
                        keys.add(u)
                        keys.add(f"{u}@{dom}")
                for k in keys:
                    acct_by_key.setdefault(k, (username_full, username, password, nt_hash))

            for ufull, uname, pw, nth in acct_rows:
                _acct_index(ufull, uname, pw, nth)

            def _acct_lookup(meta: BHNodeMeta) -> Optional[Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]]:
                keys = set()
                if meta.samaccountname:
                    keys.add(meta.samaccountname.lower())
                if meta.name:
                    nl = meta.name.lower()
                    keys.add(nl)
                    if "@" in nl:
                        keys.add(nl.split("@", 1)[0])
                for k in keys:
                    if k in acct_by_key:
                        return acct_by_key[k]
                return None

            kerb_rows = []
            for meta in sorted(bh_kerb, key=lambda m: ((m.samaccountname or m.name or "").lower())):
                acct = _acct_lookup(meta)
                password = acct[2] if acct else None
                nt_hash = acct[3] if acct else None
                cracked_str = "Yes" if (password is not None) else "No"
                plen = len(password) if password else 0
                tz_str = "Unknown"
                if meta.tier_zero is True:
                    tz_str = "Yes"
                elif meta.tier_zero is False:
                    tz_str = "No"

                display_user = meta.samaccountname or meta.name or ""
                row = (display_user, cracked_str, password or "", plen, nt_hash or "", tz_str, meta.objectid or "")
                row = sanitizer.sanitize_row(row, [2], [4], cfg.sanitize_output)
                kerb_rows.append(row)

            add_table_and_export(
                kerb_rows[:2000],
                ["Username", "Cracked", "Password", "Password Length", "NT Hash", "Tier Zero (BH)", "ObjectId (BH)"],
                caption="All Enabled Kerberoastable Users (BloodHound)",
            )
        else:
            r.add("<p class='text-left'><strong>All Enabled Kerberoastable Users (BloodHound)</strong>: None identified (or BloodHound enrichment not enabled).</p>")

        # Cracked & enabled (matched)
        if cracked_enabled:
            add_table_and_export(
                cracked_enabled[:500],
                ["Username", "Password", "Password Length", "NT Hash", "Kind (BH)", "ObjectId (BH)"],
                caption="Cracked & Enabled (Matched)",
            )
        else:
            r.add("<p class='text-left'><strong>Cracked & Enabled (Matched)</strong>: None identified.</p>")

        # Cracked & tier zero (matched)
        if cracked_t0:
            add_table_and_export(
                cracked_t0[:500],
                ["Username", "Password", "Password Length", "NT Hash", "Kind (BH)", "ObjectId (BH)"],
                caption="Cracked & Tier Zero (Matched)",
            )
        else:
            r.add("<p class='text-left'><strong>Cracked & Tier Zero (Matched)</strong>: None identified.</p>")

        # Cracked & enabled & tier zero (matched)
        if cracked_enabled_t0:
            add_table_and_export(
                cracked_enabled_t0[:500],
                ["Username", "Password", "Password Length", "NT Hash", "Kind (BH)", "ObjectId (BH)"],
                caption="Cracked & Enabled & Tier Zero (Matched)",
            )
        else:
            r.add("<p class='text-left'><strong>Cracked & Enabled & Tier Zero (Matched)</strong>: None identified.</p>")
    else:
        r.add("<p class='text-left'><strong>BloodHound Enrichment</strong>: Not configured. Provide --bh-url/--bh-user/--bh-pass to enable matched/enabled/tier zero sections.</p>")


    # Table: policy violations (all)
    db.cur.execute(
        """
        SELECT username_full, password, LENGTH(password) AS plen, nt_hash
        FROM accounts
        WHERE password IS NOT NULL AND LENGTH(password) < ?
        ORDER BY plen ASC, username_full
        """
        ,
        (cfg.min_password_length,),
    )
    viol_rows = db.cur.fetchall()
    viol_rows = [sanitizer.sanitize_row(row, [1], [3], cfg.sanitize_output) for row in viol_rows]
    if viol_rows:
        add_table_and_export(
            viol_rows,
            ["Username", "Password", "Password Length", "NT Hash"],
            caption=f"Password Policy Violations (< {cfg.min_password_length})",
        )
    else:
        r.add("<p class='text-left'><strong>Password Policy Violations</strong>: None detected in the cracked set.</p>")

    # Table: username == password (all)
    db.cur.execute(
        """
        SELECT username_full, password, LENGTH(password) AS plen, nt_hash
        FROM accounts
        WHERE password IS NOT NULL AND LOWER(username) = LOWER(password)
        ORDER BY username_full
        """
    )
    ueq_rows = db.cur.fetchall()
    ueq_rows = [sanitizer.sanitize_row(row, [1], [3], cfg.sanitize_output) for row in ueq_rows]
    if ueq_rows:
        add_table_and_export(
            ueq_rows,
            ["Username", "Password", "Password Length", "NT Hash"],
            caption="Accounts Using Username as Password",
        )
    else:
        r.add("<p class='text-left'><strong>Username-as-password</strong>: None detected in the cracked set.</p>")

    
    # Table: username-as-password via NTLM hash match (independent of crack status)
    db.cur.execute(
        """
        SELECT username_full, username, nt_hash, username_nt_match_variant
        FROM accounts
        WHERE username_nt_match = 1
        ORDER BY username_full
        """
    )
    ueqh_rows = db.cur.fetchall()
    ueqh_rows = [sanitizer.sanitize_row(row, [], [2], cfg.sanitize_output) for row in ueqh_rows]
    if ueqh_rows:
        add_table_and_export(
            ueqh_rows,
            ["Username", "SAM / Username", "NT Hash", "Matched Variant"],
            caption="Accounts Using Username as Password (NTLM hash match)",
        )
    else:
        r.add("<p class='text-left'><strong>Username-as-password (hash match)</strong>: None detected.</p>")

    return r.write(cfg.css_path)


# --------------------------- CLI ---------------------------

def parse_args() -> Config:
    ap = argparse.ArgumentParser(
        description="DPAT (Slim) – NTDS + potfile → HTML report",
    )
    ap.add_argument("-n", "--ntdsfile", required=True, help="NTDS file (e.g., secretsdump output)")
    ap.add_argument("-c", "--potfile", required=True, help="Hashcat potfile (hash:password)")
    ap.add_argument("-p", "--minpasslen", type=int, required=True, help="Minimum domain password length")
    ap.add_argument("-o", "--outputfile", default="_DomainPasswordAuditReport.html", help="HTML report filename")
    ap.add_argument("-d", "--reportdirectory", default="DPAT Report", help="Output directory")
    ap.add_argument("-s", "--sanitize", action="store_true", help="Sanitize passwords/hashes in report output")
    ap.add_argument("-m", "--machineaccts", action="store_true", help="Include machine accounts (ending with $)")
    ap.add_argument("-k", "--krbtgt", action="store_true", help="Include krbtgt account")
    ap.add_argument("--css", dest="css_path", help="Path to report.css (defaults to ./report.css if present)")
    ap.add_argument("--no-prompt", action="store_true", help="Ignored (kept for compatibility)")

    # Optional BloodHound CE enrichment
    ap.add_argument("--bh-url", help="BloodHound CE base URL (e.g., https://127.0.0.1:8080/)")
    ap.add_argument("--bh-user", dest="bh_username", help="BloodHound username (for /api/v2/login)")
    ap.add_argument("--bh-pass", dest="bh_password", help="BloodHound password (for /api/v2/login)")
    ap.add_argument("--bh-no-verify", action="store_true", help="Disable TLS certificate verification for BloodHound URL")
    ap.add_argument("--bh-timeout", type=int, default=30, help="BloodHound API timeout (seconds)")
    args = ap.parse_args()

    return Config(
        ntds_file=args.ntdsfile,
        potfile=args.potfile,
        min_password_length=args.minpasslen,
        output_file=args.outputfile,
        report_directory=args.reportdirectory,
        sanitize_output=args.sanitize,
        include_machine_accounts=args.machineaccts,
        include_krbtgt=args.krbtgt,
        css_path=args.css_path,
        no_prompt=True,
        bh_url=args.bh_url,
        bh_username=args.bh_username,
        bh_password=args.bh_password,
        bh_verify_tls=not args.bh_no_verify,
        bh_timeout=args.bh_timeout,
    )


def main() -> int:
    cfg = parse_args()
    Path(cfg.report_directory).mkdir(parents=True, exist_ok=True)

    db = DB()
    try:
        load_ntds(cfg, db)
        compute_username_hash_matches(cfg, db)
        apply_potfile(cfg, db)
        report_path = build_report(cfg, db)
        logger.info("Done. Open: %s", report_path)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())