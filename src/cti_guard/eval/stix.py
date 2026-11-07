"""Extract reference IOC from a STIX 2.1 bundle published by the advisory's own authors.

Only ``indicator`` patterns of the simple form ``[type:path = 'value']`` (combined with OR/AND)
and ``vulnerability`` objects named ``CVE-...`` are read. Values are canonicalised with the same
rules the systems under test use, so comparison is purely on (type, canonical value).
"""

from __future__ import annotations

import json
import re

from cti_guard.domain.entities import IOCType
from cti_guard.eval.corpus import Key
from cti_guard.eval.systems import TYPE_TO_WIRE
from cti_guard.security.verifier import canonicalize

_COMPARISON = re.compile(
    r"(?P<obj>[a-z0-9-]+):(?P<path>[A-Za-z0-9_.'\"-]+)\s*(?:=|LIKE)\s*'(?P<val>(?:[^'\\]|\\.)*)'"
)
_HASH_KEYS = {
    "MD5": IOCType.FILE_HASH_MD5,
    "SHA-1": IOCType.FILE_HASH_SHA1,
    "SHA-256": IOCType.FILE_HASH_SHA256,
}


def _type_for(obj: str, path: str) -> IOCType | None:
    if obj == "ipv4-addr" or obj == "ipv6-addr":
        return IOCType.IP_ADDRESS
    if obj == "domain-name":
        return IOCType.DOMAIN
    if obj == "url":
        return IOCType.URL
    if obj == "file" and path.startswith("hashes"):
        for key, t in _HASH_KEYS.items():
            if key in path.replace("'", "").replace('"', "").upper():
                return t
    return None


def stix_iocs(bundle_json: str) -> set[Key]:
    """Reference IOC (wire type, canonical value) found in the bundle."""
    data = json.loads(bundle_json)
    out: set[Key] = set()
    for obj in data.get("objects", []):
        kind = obj.get("type")
        if kind == "indicator":
            for m in _COMPARISON.finditer(obj.get("pattern", "")):
                ioc_type = _type_for(m["obj"], m["path"])
                if ioc_type is None:
                    continue
                canon = canonicalize(ioc_type, m["val"].replace("\\'", "'"))
                if canon:
                    out.add((TYPE_TO_WIRE[ioc_type], canon))
        elif kind == "vulnerability":
            canon = canonicalize(IOCType.CVE_ID, str(obj.get("name", "")))
            if canon:
                out.add(("cve", canon))
        elif kind in ("ipv4-addr", "ipv6-addr", "domain-name", "url"):  # SCOs
            ioc_type = _type_for(kind, "value")
            canon = canonicalize(ioc_type, str(obj.get("value", ""))) if ioc_type else None
            if ioc_type and canon:
                out.add((TYPE_TO_WIRE[ioc_type], canon))
        elif kind == "file":
            for k, v in (obj.get("hashes") or {}).items():
                ioc_type = _HASH_KEYS.get(k.upper())
                canon = canonicalize(ioc_type, str(v)) if ioc_type else None
                if ioc_type and canon:
                    out.add((TYPE_TO_WIRE[ioc_type], canon))
    return out


_XML_HASHES = {
    "MD5": IOCType.FILE_HASH_MD5,
    "SHA1": IOCType.FILE_HASH_SHA1,
    "SHA256": IOCType.FILE_HASH_SHA256,
}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def stix1_xml_iocs(xml_text: str) -> set[Key]:
    """Reference IOC from a STIX 1.x XML package (older CISA advisories). Uses defusedxml."""
    from defusedxml import ElementTree as ET

    root = ET.fromstring(xml_text)
    out: set[Key] = set()

    def add(ioc_type: IOCType, raw: str) -> None:
        for piece in (raw or "").split("##comma##"):
            canon = canonicalize(ioc_type, piece.strip())
            if canon:
                out.add((TYPE_TO_WIRE[ioc_type], canon))

    xsi = "{http://www.w3.org/2001/XMLSchema-instance}type"
    for el in root.iter():
        name = _local(el.tag)
        if name == "CVE_ID":
            add(IOCType.CVE_ID, (el.text or "").strip())
        kind = _local(el.get(xsi, ""))
        children = {_local(c.tag): c for c in el}
        if kind == "AddressObjectType" and el.get("category", "ipv4-addr") in (
            "ipv4-addr",
            "ipv6-addr",
        ):
            add(
                IOCType.IP_ADDRESS, (children["Address_Value"].text or "").strip()
            ) if "Address_Value" in children else None
        elif kind == "DomainNameObjectType" and "Value" in children:
            add(IOCType.DOMAIN, (children["Value"].text or "").strip())
        elif kind == "URIObjectType" and "Value" in children:
            add(IOCType.URL, (children["Value"].text or "").strip())
        elif name == "Hash":
            htype = (
                (children["Type"].text or "").strip().upper().replace("-", "")
                if "Type" in children
                else ""
            )
            val = (
                (children["Simple_Hash_Value"].text or "").strip()
                if "Simple_Hash_Value" in children
                else ""
            )
            if htype in _XML_HASHES:
                add(_XML_HASHES[htype], val)
    return out
