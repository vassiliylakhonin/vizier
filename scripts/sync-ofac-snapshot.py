"""Fetch official OFAC SDN XML and produce a bounded, exact-match EVM address snapshot."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

SOURCE = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.XML"
NS = {"o": "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML"}
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
MAX_BYTES = 40 * 1024 * 1024


def build_snapshot(raw: bytes, checked_at: int) -> dict[str, object]:
    if not 1_000_000 <= len(raw) <= MAX_BYTES or b"<!DOCTYPE" in raw.upper():
        raise ValueError("OFAC XML size or DTD is unexpected")
    root = ET.fromstring(raw)
    if root.tag != f"{{{NS['o']}}}sdnList":
        raise ValueError("Unexpected OFAC XML root")
    info = root.find("o:publshInformation", NS)
    if info is None:
        raise ValueError("OFAC publication metadata missing")
    count = int(info.findtext("o:Record_Count", namespaces=NS) or "0")
    entries = root.findall("o:sdnEntry", NS)
    if count != len(entries) or count < 10000:
        raise ValueError("OFAC record count incomplete")
    published = datetime.strptime(info.findtext("o:Publish_Date", namespaces=NS) or "", "%m/%d/%Y").date()
    if (datetime.utcfromtimestamp(checked_at).date() - published).days < 0:
        raise ValueError("OFAC publication date is in the future")
    addresses: set[str] = set()
    for entry in entries:
        for identity in entry.findall(".//o:id", NS):
            kind = identity.findtext("o:idType", default="", namespaces=NS)
            value = identity.findtext("o:idNumber", default="", namespaces=NS).strip()
            if kind.startswith("Digital Currency Address") and ADDRESS.fullmatch(value):
                addresses.add(value.lower())
    if not 100 <= len(addresses) <= 10000:
        raise ValueError("OFAC EVM address count is unexpected")
    return {"schema_version": 1, "source": SOURCE, "checked_at": checked_at,
            "publish_date": published.isoformat(), "source_sha256": hashlib.sha256(raw).hexdigest(),
            "record_count": count, "addresses": sorted(addresses)}


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: sync-ofac-snapshot.py OUTPUT_JSON")
    request = urllib.request.Request(SOURCE, headers={"User-Agent": "Vizier-OFAC-SDN-Snapshot/1.0 (+https://github.com/vassiliylakhonin/vizier)"})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(MAX_BYTES + 1)
    snapshot = build_snapshot(raw, int(time.time()))
    Path(sys.argv[1]).write_text(json.dumps(snapshot, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"OFAC SDN snapshot: {snapshot['record_count']} records, {len(snapshot['addresses'])} EVM addresses, published {snapshot['publish_date']}")


if __name__ == "__main__":
    main()
