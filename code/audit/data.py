"""Loading of the tabular inputs and identity resolution."""
from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass, field


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


@dataclass
class Identity:
    user_ids: set = field(default_factory=set)
    emails: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    names: set = field(default_factory=set)
    audit_ids: list = field(default_factory=list)   # audit_log rows that prove a historical identifier

    def keys(self) -> set:
        return {k.lower() for k in (self.user_ids | self.emails | self.phones | self.hashes | self.names)}

    def strong_keys(self) -> set:
        """Identifiers that are unique to a person (names are not)."""
        return {k.lower() for k in (self.user_ids | self.emails | self.phones | self.hashes)}


class World:
    """All participant-facing tabular data."""

    def __init__(self, dataset_dir: str):
        self.dir = dataset_dir
        self.identities = read_csv(os.path.join(dataset_dir, "user_identities.csv"))
        self.audit_log = read_csv(os.path.join(dataset_dir, "user_audit_log.csv"))
        self.activities = read_csv(os.path.join(dataset_dir, "system_activity.csv"))
        self.rules = read_csv(os.path.join(dataset_dir, "deletion_rules.csv"))
        self.by_user = {r["user_id"]: r for r in self.identities}
        # email -> user ids (current and historical), lower-cased
        self.email_index: dict[str, set] = {}
        for r in self.identities:
            self.email_index.setdefault(r["email"].lower(), set()).add(r["user_id"])
        for a in self.audit_log:
            if a["field_name"] == "email":
                for v in (a["old_value"], a["new_value"]):
                    self.email_index.setdefault(v.lower(), set()).add(a["user_id"])

    def resolve(self, email: str) -> Identity:
        ident = Identity()
        email = email.strip().lower()
        ident.emails.add(email)
        for uid in sorted(self.email_index.get(email, set())):
            u = self.by_user[uid]
            ident.user_ids.add(uid)
            ident.emails.add(u["email"].lower())
            ident.phones.add(u["phone"])
            ident.hashes.add(u["email_hash"].lower())
            ident.names.add(u["name"])
            for a in self.audit_log:
                if a["user_id"] != uid:
                    continue
                ident.audit_ids.append(a["audit_id"])
                for v in (a["old_value"], a["new_value"]):
                    if a["field_name"] == "email":
                        ident.emails.add(v.lower())
                    elif a["field_name"] == "phone":
                        ident.phones.add(v)
                    elif a["field_name"] == "email_hash":
                        ident.hashes.add(v.lower())
        return ident


def parse_ts(s: str):
    from datetime import datetime, timezone
    s = s.strip()
    if not s:
        return None
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


_DIGITS = re.compile(r"\D+")


def phone_key(p: str) -> str:
    return _DIGITS.sub("", p or "")
