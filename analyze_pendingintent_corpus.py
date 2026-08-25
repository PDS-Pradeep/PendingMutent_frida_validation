#!/usr/bin/env python3

"""
PendingMutent APK Corpus Analyzer  (corrected)
==============================================

Purpose
-------
Static candidate discovery for a corpus of Android APKs.

Input (edit REPOSITORIES below):
    android_repositories/
        fdroid_main/
        izzyondroid/

Output:
    android_repositories/pendingintent_analysis/

The analyzer identifies candidates for:
    v1 = Fill-in Intent / mutable PendingIntent
    v2 = Privilege / permission boundary
    v3 = PendingIntent cancel / ownership

IMPORTANT
---------
This is STATIC TRIAGE. A v1/v2/v3 score does NOT prove exploitability.
Candidates must be validated dynamically with the Frida + MalwareApp experiment.

Fixes vs the original draft
---------------------------
1. androguard 4.x returns MethodAnalysis objects whose name/class/descriptor are
   PROPERTIES, not get_*() methods. Version-tolerant accessors added; without
   this every APK silently reported 0 PendingIntent calls.
2. Mutability flags are folded into a single integer constant at compile time
   (e.g. FLAG_UPDATE_CURRENT | FLAG_MUTABLE -> 0x0A000000). Exact-string matching
   missed them. Flags are now detected by testing the BITS of every integer
   literal operand in the caller method.
3. Results are streamed to analysis.jsonl as they are produced, so a long run
   over large mirrors cannot lose everything to an OOM at the end.
4. REPOSITORIES trimmed to the two mirrors actually in use.
5. The category fallback comment now reflects what the code really does
   (strict, no cross-category padding).
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
import sys
import time
import traceback

from pathlib import Path
from collections import defaultdict
from typing import Any, Dict, List, Tuple

# Silence androguard's very verbose DEBUG/INFO logging (loguru-based in 4.x).
# Without this, every AXML attribute and instruction decode prints a line,
# which measurably slows down large-corpus runs.
try:
    from loguru import logger as _loguru_logger
    _loguru_logger.remove()
except Exception:
    pass

from androguard.core.apk import APK
from androguard.core.dex import DEX


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path("android_repositories")

REPOSITORIES = [
    BASE_DIR / "fdroid_main",
    BASE_DIR / "izzyondroid",
]

OUTPUT_DIR = BASE_DIR / "pendingintent_analysis"
REPORT_DIR = OUTPUT_DIR / "reports"
CANDIDATE_DIR = OUTPUT_DIR / "candidates"
SELECTED_DIR = OUTPUT_DIR / "selected_13"

MAX_EVIDENCE_PER_CATEGORY = 100

# Number wanted for your experiment
TARGET_V1 = 5
TARGET_V2 = 5
TARGET_V3 = 3


# ============================================================
# PENDINGINTENT API DEFINITIONS
# ============================================================

PI_CLASS = "Landroid/app/PendingIntent;"

PI_CREATION_METHODS = {
    "getActivity",
    "getActivities",
    "getBroadcast",
    "getForegroundService",
    "getService",
}

PI_OPERATION_METHODS = {
    "send",
    "cancel",
    "getIntentSender",
}

ALL_PI_METHODS = PI_CREATION_METHODS | PI_OPERATION_METHODS


# ============================================================
# MUTABILITY FLAGS  (bit values)
# ============================================================

FLAG_MUTABLE = 0x02000000
FLAG_IMMUTABLE = 0x04000000
FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT = 0x01000000


# ============================================================
# STRING / API INDICATORS
# ============================================================

FILL_IN_INDICATORS = [
    "fillIn",
    "FILL_IN_ACTION",
    "FILL_IN_DATA",
    "FILL_IN_CATEGORIES",
    "FILL_IN_COMPONENT",
    "FILL_IN_PACKAGE",
    "FILL_IN_SELECTOR",
    "FILL_IN_CLIP_DATA",
]

INTENT_EXTERNAL_SOURCE_INDICATORS = [
    "getParcelableExtra",
    "getParcelableArrayExtra",
    "getExtras",
    "getBundleExtra",
    "getIntent",
]

OWNERSHIP_INDICATORS = [
    "getCreatorUid",
    "getCreatorPackage",
    "getTargetPackage",
    "getTarget",
    "getCallingUid",
    "getCallingPid",
    "getSentFromUid",
    "getSentFromPackage",
]

PERMISSION_INDICATORS = [
    "checkCallingPermission",
    "checkCallingOrSelfPermission",
    "checkPermission",
    "enforceCallingPermission",
    "enforceCallingOrSelfPermission",
    "getCallingUid",
    "getCallingPid",
    "android.permission.",
]

EXPLICIT_INTENT_INDICATORS = [
    "setComponent",
    "setClass",
    "setClassName",
    "setPackage",
    "ComponentName",
]

IMPLICIT_INTENT_INDICATORS = [
    "setAction",
    "setData",
    "addCategory",
    "setType",
]


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def ensure_directories() -> None:

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
    SELECTED_DIR.mkdir(parents=True, exist_ok=True)

    for category in ["v1", "v2", "v3", "mixed"]:
        (CANDIDATE_DIR / category).mkdir(parents=True, exist_ok=True)

    for category in ["v1", "v2", "v3"]:
        (SELECTED_DIR / category).mkdir(parents=True, exist_ok=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return ""


def unique_list(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


# ============================================================
# VERSION-TOLERANT ANDROGUARD ACCESSORS
# ------------------------------------------------------------
# androguard 3.x exposed get_name()/get_class_name()/get_descriptor()
# as methods.  androguard 4.x exposes them as PROPERTIES on
# MethodAnalysis (name / class_name / descriptor).  These helpers work
# on both so the corpus scan does not silently return 0 PI calls.
# ============================================================

def _call_or_attr(obj, method_name, attr_name, default=""):
    f = getattr(obj, method_name, None)
    if callable(f):
        try:
            return f()
        except Exception:
            pass
    v = getattr(obj, attr_name, None)
    return v if v is not None else default


def m_name(m) -> str:
    return safe_str(_call_or_attr(m, "get_name", "name", ""))


def m_class(m) -> str:
    return safe_str(_call_or_attr(m, "get_class_name", "class_name", ""))


def m_descriptor(m) -> str:
    return safe_str(_call_or_attr(m, "get_descriptor", "descriptor", ""))


def method_signature(method) -> str:
    try:
        return f"{m_class(method)}->{m_name(method)}{m_descriptor(method)}"
    except Exception:
        return safe_str(method)


def get_encoded_method(method_analysis):
    """
    Return an object that exposes get_instructions().
    MethodAnalysis -> get_method(); an already-encoded method -> itself.
    """
    gm = getattr(method_analysis, "get_method", None)
    if callable(gm):
        try:
            em = gm()
            if em is not None:
                return em
        except Exception:
            pass
    if getattr(method_analysis, "get_instructions", None):
        return method_analysis
    return None


def get_method_instructions(method_analysis):
    """
    Returns: [(offset, instruction_text), ...]
    """
    result = []
    encoded = get_encoded_method(method_analysis)
    if encoded is None:
        return result

    try:
        offset = 0
        for instruction in encoded.get_instructions():
            try:
                text = instruction.get_output(offset)
            except Exception:
                text = None
            if text is None:
                try:
                    text = instruction.get_name()
                except Exception:
                    text = ""
            result.append((offset, safe_str(text)))
            try:
                offset += instruction.get_length()
            except Exception:
                offset += 1
    except Exception:
        try:
            for instruction in encoded.get_instructions():
                result.append((-1, safe_str(instruction.get_name())))
        except Exception:
            pass

    return result


def method_text(method_analysis) -> str:
    return "\n".join(text for _, text in get_method_instructions(method_analysis))


# ============================================================
# INSTRUCTION SEARCH  (string indicators)
# ============================================================

def search_method_indicators(method_analysis, indicators: List[str]) -> List[Dict[str, Any]]:
    evidence = []
    for offset, text in get_method_instructions(method_analysis):
        lower = text.lower()
        for indicator in indicators:
            if indicator.lower() in lower:
                evidence.append({
                    "offset": offset,
                    "indicator": indicator,
                    "instruction": text,
                })
    return evidence


# ============================================================
# FLAG-BIT DETECTION  (folded integer constants)
# ------------------------------------------------------------
# FLAG_UPDATE_CURRENT | FLAG_MUTABLE is folded by the compiler into a
# single const operand, so matching exact strings like "0x02000000"
# misses the common case.  Instead, extract every integer literal in
# the method and test whether the requested flag bit is set.
# ============================================================

_INT_RE = re.compile(r"(?<![\w.])(-?0x[0-9a-fA-F]+|-?\d+)(?![\w.])")


def _literal_ints(text: str) -> List[int]:
    out = []
    for tok in _INT_RE.findall(text):
        try:
            if tok.lower().lstrip("-").startswith("0x"):
                out.append(int(tok, 16))
            else:
                out.append(int(tok))
        except Exception:
            pass
    return out


def flag_bit_hits(method_analysis, flag_bit: int) -> int:
    """Count const operands whose value has flag_bit set (catches folded flags)."""
    hits = 0
    for _, text in get_method_instructions(method_analysis):
        for val in _literal_ints(text):
            if val & flag_bit:
                hits += 1
    return hits


# ============================================================
# APK DISCOVERY
# ============================================================

def discover_apks() -> List[Path]:

    print()
    print("=" * 80)
    print("DISCOVERING APKs")
    print("=" * 80)

    all_apks = []

    for repo in REPOSITORIES:
        print(f"\nRepository: {repo}")
        if not repo.exists():
            print("  WARNING: directory does not exist")
            continue
        repo_apks = list(repo.rglob("*.apk"))
        print(f"  APKs found: {len(repo_apks)}")
        all_apks.extend(repo_apks)

    # Remove duplicate physical paths.
    unique = {}
    for apk in all_apks:
        unique[str(apk.resolve())] = apk

    result = sorted(unique.values(), key=lambda p: str(p).lower())
    print()
    print(f"TOTAL UNIQUE APKs: {len(result)}")
    return result


# ============================================================
# PENDINGINTENT METHOD DISCOVERY
# ============================================================

# Matches "Landroid/app/PendingIntent;->methodName(" inside a decoded
# invoke-* instruction's text, e.g.:
#   invoke-static {..}, Landroid/app/PendingIntent;->getActivity(...)...
_PI_CALL_RE = re.compile(
    r"Landroid/app/PendingIntent;->([A-Za-z_][A-Za-z0-9_]*)\("
)


def find_pendingintent_methods(dex_objs) -> Tuple[Any, Any]:
    """
    Scan every method's decoded instructions directly for invocations of
    android.app.PendingIntent.* APIs.

    This replaces the previous approach of building a full androguard
    Analysis()/XREF graph (via dx.find_methods(...).get_xref_from()), which
    requires cross-referencing every method against every other method in
    the app and does not scale: on large/obfuscated APKs (Cordova, heavy
    multidex, Compose apps) that graph construction alone was taking tens
    of minutes to over an hour per APK. A single linear pass over each
    method's own instructions finds the exact same callers in a fraction
    of the time (no XREF graph needed) because we already know which
    method we're iterating when we hit a PendingIntent invoke.

    Returns: dict  api_method_name -> list of caller dicts
    """
    api_callers = defaultdict(list)

    for d in dex_objs:
        try:
            methods = d.get_encoded_methods()
        except Exception:
            continue

        for method in methods:
            try:
                instructions = get_method_instructions(method)
            except Exception:
                continue

            if not instructions:
                continue

            signature = None  # computed lazily, only if this method has a PI call

            for offset, text in instructions:
                match = _PI_CALL_RE.search(text)
                if not match:
                    continue

                name = match.group(1)
                if name not in ALL_PI_METHODS:
                    continue

                if signature is None:
                    signature = method_signature(method)

                api_callers[name].append({
                    "caller": signature,
                    "offset": offset,
                    "caller_method": method,
                })

    return api_callers


# ============================================================
# MANIFEST ANALYSIS
# ============================================================

def analyze_manifest(apk) -> Dict[str, Any]:

    result = {
        "package": "",
        "target_sdk": None,
        "min_sdk": None,
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
        "permissioned_components": [],
        "permissions": [],
    }

    try:
        result["package"] = apk.get_package()
    except Exception:
        pass

    for field, key in [
        ("get_target_sdk_version", "target_sdk"),
        ("get_min_sdk_version", "min_sdk"),
    ]:
        try:
            result[key] = getattr(apk, field)()
        except Exception:
            pass

    try:
        result["permissions"] = sorted(unique_list(list(apk.get_permissions())))
    except Exception:
        pass

    for getter, output_key in [
        ("get_activities", "activities"),
        ("get_services", "services"),
        ("get_receivers", "receivers"),
        ("get_providers", "providers"),
    ]:
        try:
            result[output_key] = sorted(unique_list(list(getattr(apk, getter)())))
        except Exception:
            pass

    # XML-based exported / permissioned component detection
    try:
        axml = apk.get_android_manifest_xml()
        if axml is not None:
            for element in axml.iter():
                tag = safe_str(element.tag).lower()
                if "activity" in tag:
                    component_type = "activity"
                elif "service" in tag:
                    component_type = "service"
                elif "receiver" in tag:
                    component_type = "receiver"
                elif "provider" in tag:
                    component_type = "provider"
                else:
                    continue

                try:
                    attrs = dict(element.attrib)
                except Exception:
                    attrs = {}

                exported = (
                    attrs.get("{http://schemas.android.com/apk/res/android}exported")
                    or attrs.get("android:exported")
                )
                permission = (
                    attrs.get("{http://schemas.android.com/apk/res/android}permission")
                    or attrs.get("android:permission")
                )
                name = (
                    attrs.get("{http://schemas.android.com/apk/res/android}name")
                    or attrs.get("android:name")
                    or ""
                )

                if safe_str(exported).lower() == "true":
                    result["exported_components"].append(
                        {"type": component_type, "name": name}
                    )
                if permission:
                    result["permissioned_components"].append(
                        {"type": component_type, "name": name, "permission": permission}
                    )
    except Exception:
        pass

    return result


# ============================================================
# CANDIDATE ANALYSIS
# ============================================================

def analyze_apk(apk_path: Path, index: int, total: int) -> Dict[str, Any]:

    print()
    print(f"[{index}/{total}] {apk_path.name}")

    started = time.time()

    result = {
        "apk": str(apk_path.resolve()),
        "filename": apk_path.name,
        "sha256": "",
        "status": "ERROR",
        "analysis_seconds": 0,
        "package": "",
        "target_sdk": None,
        "min_sdk": None,

        "pendingintent_create_calls": 0,
        "pendingintent_send_calls": 0,
        "pendingintent_cancel_calls": 0,
        "pendingintent_intentsender_calls": 0,

        "mutable_hits": 0,
        "immutable_hits": 0,
        "unsafe_implicit_hits": 0,

        "fillin_hits": 0,
        "external_pi_source_hits": 0,
        "ownership_hits": 0,
        "permission_hits": 0,
        "explicit_intent_hits": 0,
        "implicit_intent_hits": 0,

        "activity_count": 0,
        "service_count": 0,
        "receiver_count": 0,
        "provider_count": 0,
        "exported_component_count": 0,
        "permissioned_component_count": 0,
        "permission_count": 0,

        "v1_score": 0,
        "v2_score": 0,
        "v3_score": 0,
        "max_score": 0,
        "classification": "none",

        "evidence": {"v1": [], "v2": [], "v3": [], "pendingintent_apis": []},
        "manifest": {},
    }

    try:
        result["sha256"] = sha256_file(apk_path)

        apk = APK(str(apk_path))
        dex_objs = [DEX(raw) for raw in apk.get_all_dex()]

        manifest = analyze_manifest(apk)
        result["manifest"] = manifest
        result["package"] = manifest.get("package") or ""
        result["target_sdk"] = manifest.get("target_sdk")
        result["min_sdk"] = manifest.get("min_sdk")

        result["activity_count"] = len(manifest.get("activities", []))
        result["service_count"] = len(manifest.get("services", []))
        result["receiver_count"] = len(manifest.get("receivers", []))
        result["provider_count"] = len(manifest.get("providers", []))
        result["exported_component_count"] = len(manifest.get("exported_components", []))
        result["permissioned_component_count"] = len(manifest.get("permissioned_components", []))
        result["permission_count"] = len(manifest.get("permissions", []))

        # ---- PendingIntent API calls (direct bytecode scan, no XREF graph) ----
        api_callers = find_pendingintent_methods(dex_objs)

        all_caller_methods = []
        for api_name, callers in api_callers.items():
            for caller in callers:
                result["evidence"]["pendingintent_apis"].append({
                    "api": api_name,
                    "caller": caller["caller"],
                    "offset": caller["offset"],
                })
                all_caller_methods.append(
                    (api_name, caller["caller_method"], caller["offset"])
                )

        result["pendingintent_create_calls"] = sum(
            len(api_callers.get(name, [])) for name in PI_CREATION_METHODS
        )
        result["pendingintent_send_calls"] = len(api_callers.get("send", []))
        result["pendingintent_cancel_calls"] = len(api_callers.get("cancel", []))
        result["pendingintent_intentsender_calls"] = len(api_callers.get("getIntentSender", []))

        # ---- Analyze unique caller methods ----
        seen_methods = set()

        for api_name, caller_method, call_offset in all_caller_methods:

            signature = method_signature(caller_method)
            if signature in seen_methods:
                continue
            seen_methods.add(signature)

            # Mutability flags — BIT test on folded constants
            mutable_n = flag_bit_hits(caller_method, FLAG_MUTABLE)
            immutable_n = flag_bit_hits(caller_method, FLAG_IMMUTABLE)
            unsafe_n = flag_bit_hits(caller_method, FLAG_ALLOW_UNSAFE_IMPLICIT_INTENT)

            result["mutable_hits"] += mutable_n
            result["immutable_hits"] += immutable_n
            result["unsafe_implicit_hits"] += unsafe_n

            # String / API indicators (survive compilation)
            fillin_evidence = search_method_indicators(caller_method, FILL_IN_INDICATORS)
            external_evidence = search_method_indicators(caller_method, INTENT_EXTERNAL_SOURCE_INDICATORS)
            ownership_evidence = search_method_indicators(caller_method, OWNERSHIP_INDICATORS)
            permission_evidence = search_method_indicators(caller_method, PERMISSION_INDICATORS)
            explicit_evidence = search_method_indicators(caller_method, EXPLICIT_INTENT_INDICATORS)
            implicit_evidence = search_method_indicators(caller_method, IMPLICIT_INTENT_INDICATORS)

            result["fillin_hits"] += len(fillin_evidence)
            result["external_pi_source_hits"] += len(external_evidence)
            result["ownership_hits"] += len(ownership_evidence)
            result["permission_hits"] += len(permission_evidence)
            result["explicit_intent_hits"] += len(explicit_evidence)
            result["implicit_intent_hits"] += len(implicit_evidence)

            evidence_base = {
                "api": api_name,
                "caller": signature,
                "call_offset": call_offset,
            }

            if mutable_n or fillin_evidence or unsafe_n:
                result["evidence"]["v1"].append({
                    **evidence_base,
                    "mutable_bit_hits": mutable_n,
                    "immutable_bit_hits": immutable_n,
                    "unsafe_implicit_bit_hits": unsafe_n,
                    "fillin": fillin_evidence,
                    "explicit_intent": explicit_evidence,
                    "implicit_intent": implicit_evidence,
                })

            if permission_evidence or manifest["exported_components"] or external_evidence:
                result["evidence"]["v2"].append({
                    **evidence_base,
                    "permission": permission_evidence,
                    "exported_components": manifest["exported_components"],
                    "external_source": external_evidence,
                })

            if api_name == "cancel" or ownership_evidence or external_evidence:
                result["evidence"]["v3"].append({
                    **evidence_base,
                    "ownership": ownership_evidence,
                    "external_source": external_evidence,
                    "cancel": api_name == "cancel",
                })

        # ---- SCORE V1 ----
        v1 = 0
        if result["pendingintent_create_calls"] > 0:
            v1 += 3
        if result["mutable_hits"] > 0:
            v1 += 6
        if result["fillin_hits"] > 0:
            v1 += 5
        if result["pendingintent_send_calls"] > 0:
            v1 += 2
        if result["mutable_hits"] > 0 and result["immutable_hits"] == 0:
            v1 += 3
        if result["unsafe_implicit_hits"] > 0:
            v1 += 4
        if result["implicit_intent_hits"] > 0 and result["mutable_hits"] > 0:
            v1 += 4
        result["v1_score"] = v1

        # ---- SCORE V2 ----
        v2 = 0
        if result["pendingintent_create_calls"] > 0:
            v2 += 3
        if result["exported_component_count"] > 0:
            v2 += 3
        if result["permissioned_component_count"] > 0:
            v2 += 3
        if result["permission_hits"] > 0:
            v2 += 4
        if result["external_pi_source_hits"] > 0:
            v2 += 4
        if result["pendingintent_send_calls"] > 0:
            v2 += 2
        if result["exported_component_count"] > 0 and result["permission_hits"] == 0:
            v2 += 3
        result["v2_score"] = v2

        # ---- SCORE V3 ----
        v3 = 0
        if result["pendingintent_cancel_calls"] > 0:
            v3 += 8
        if result["external_pi_source_hits"] > 0:
            v3 += 5
        if result["ownership_hits"] > 0:
            v3 += 2
        if result["permission_hits"] > 0:
            v3 += 2
        if result["pendingintent_cancel_calls"] > 0 and result["ownership_hits"] == 0:
            v3 += 5
        if result["pendingintent_cancel_calls"] > 0 and result["external_pi_source_hits"] > 0:
            v3 += 5
        result["v3_score"] = v3

        # ---- Classification ----
        scores = {"v1": v1, "v2": v2, "v3": v3}
        result["max_score"] = max(scores.values())
        strong = [c for c, s in scores.items() if s >= 10]
        if len(strong) >= 2:
            result["classification"] = "mixed"
        elif len(strong) == 1:
            result["classification"] = strong[0]
        else:
            result["classification"] = "none"

        # ---- Limit evidence ----
        for category in ["v1", "v2", "v3", "pendingintent_apis"]:
            result["evidence"][category] = result["evidence"][category][:MAX_EVIDENCE_PER_CATEGORY]

        result["status"] = "OK"

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = safe_str(e)
        result["traceback"] = traceback.format_exc()

    result["analysis_seconds"] = round(time.time() - started, 2)

    print(f"  Package : {result.get('package', '')}")
    print(f"  PI      : create={result['pendingintent_create_calls']} "
          f"send={result['pendingintent_send_calls']} "
          f"cancel={result['pendingintent_cancel_calls']}")
    print(f"  Flags   : mutable={result['mutable_hits']} "
          f"immutable={result['immutable_hits']} "
          f"unsafe={result['unsafe_implicit_hits']}")
    print(f"  Scores  : v1={result['v1_score']} "
          f"v2={result['v2_score']} v3={result['v3_score']}")
    print(f"  Class   : {result['classification']}")
    if result["status"] == "ERROR":
        print(f"  ERROR   : {result.get('error', '')}")

    return result


# ============================================================
# CSV WRITER
# ============================================================

CSV_FIELDS = [
    "apk", "filename", "sha256", "status", "package",
    "target_sdk", "min_sdk",
    "pendingintent_create_calls", "pendingintent_send_calls",
    "pendingintent_cancel_calls", "pendingintent_intentsender_calls",
    "mutable_hits", "immutable_hits", "unsafe_implicit_hits",
    "fillin_hits", "external_pi_source_hits",
    "ownership_hits", "permission_hits",
    "explicit_intent_hits", "implicit_intent_hits",
    "activity_count", "service_count", "receiver_count", "provider_count",
    "exported_component_count", "permissioned_component_count", "permission_count",
    "v1_score", "v2_score", "v3_score",
    "max_score", "classification", "analysis_seconds",
]


def write_csv(filename: Path, records: List[Dict[str, Any]]):
    with filename.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            writer.writerow(record)


# ============================================================
# COPY CANDIDATES
# ============================================================

def copy_candidate(record, category, rank, destination_root):
    source = Path(record["apk"])
    if not source.exists():
        return None

    destination_dir = destination_root / category
    destination_dir.mkdir(parents=True, exist_ok=True)

    package = record.get("package") or "unknown"
    safe_package = package.replace("/", "_").replace("\\", "_").replace(":", "_")
    destination = destination_dir / f"{rank:02d}_{safe_package}_{source.name}"

    try:
        shutil.copy2(source, destination)
        return destination
    except Exception as e:
        print(f"Could not copy {source}: {e}")
        return None


# ============================================================
# RANKING
# ============================================================

def rank_records(records, category):
    score_key = f"{category}_score"
    candidates = [
        r for r in records
        if r.get("status") == "OK"
        and r.get(score_key, 0) > 0
        and r.get("pendingintent_create_calls", 0) > 0
    ]
    candidates.sort(
        key=lambda r: (
            r.get(score_key, 0),
            r.get("mutable_hits", 0),
            r.get("external_pi_source_hits", 0),
            r.get("ownership_hits", 0),
            r.get("permission_hits", 0),
            r.get("pendingintent_send_calls", 0),
            r.get("pendingintent_cancel_calls", 0),
        ),
        reverse=True,
    )
    return candidates


# ============================================================
# SELECT 13
# ============================================================

def select_13(records):
    v1_candidates = rank_records(records, "v1")
    v2_candidates = rank_records(records, "v2")
    v3_candidates = rank_records(records, "v3")

    selected_v1, selected_v2, selected_v3 = [], [], []
    used_hashes = set()

    def choose(candidates, count, output):
        for record in candidates:
            if len(output) >= count:
                break
            sha = record.get("sha256")
            if not sha or sha in used_hashes:
                continue
            output.append(record)
            used_hashes.add(sha)

    choose(v1_candidates, TARGET_V1, selected_v1)
    choose(v2_candidates, TARGET_V2, selected_v2)
    choose(v3_candidates, TARGET_V3, selected_v3)

    # NOTE: strict behaviour. If a category is short, we do NOT pad it with
    # apps from another category — a v3 slot filled by a v1 app would corrupt
    # the per-attack-class results downstream. The second pass below only
    # re-checks the SAME category list (already exhausted after `choose`),
    # so a shortfall is surfaced as a WARNING rather than silently hidden.
    def fill(output, count, candidates):
        if len(output) >= count:
            return
        for record in candidates:
            if len(output) >= count:
                break
            sha = record.get("sha256")
            if sha in used_hashes:
                continue
            output.append(record)
            used_hashes.add(sha)

    fill(selected_v1, TARGET_V1, v1_candidates)
    fill(selected_v2, TARGET_V2, v2_candidates)
    fill(selected_v3, TARGET_V3, v3_candidates)

    return selected_v1, selected_v2, selected_v3


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 80)
    print("PendingMutent Androguard Corpus Analyzer (corrected)")
    print("=" * 80)

    ensure_directories()

    apks = discover_apks()
    if not apks:
        print("\nERROR: No APKs found.")
        print("\nExpected repositories:")
        for repo in REPOSITORIES:
            print(f"  {repo}")
        sys.exit(1)

    # Stream each result to JSONL so a long run cannot lose everything at the end.
    jsonl_path = REPORT_DIR / "analysis.jsonl"
    results = []
    total = len(apks)

    with jsonl_path.open("w", encoding="utf-8") as jf:
        for index, apk in enumerate(apks, start=1):
            result = analyze_apk(apk, index, total)
            results.append(result)
            # write a compact per-record line (evidence kept, manifest dropped to save space)
            slim = {k: v for k, v in result.items() if k != "manifest"}
            jf.write(json.dumps(slim, ensure_ascii=False) + "\n")
            jf.flush()

    # Full JSON (with manifest) for completeness
    with (REPORT_DIR / "analysis.json").open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    write_csv(REPORT_DIR / "analysis.csv", results)

    v1 = rank_records(results, "v1")
    v2 = rank_records(results, "v2")
    v3 = rank_records(results, "v3")

    write_csv(REPORT_DIR / "v1_candidates.csv", v1)
    write_csv(REPORT_DIR / "v2_candidates.csv", v2)
    write_csv(REPORT_DIR / "v3_candidates.csv", v3)

    # Copy top 30 candidates per category for manual inspection
    for category, candidates in [("v1", v1), ("v2", v2), ("v3", v3)]:
        for rank, record in enumerate(candidates[:30], start=1):
            copy_candidate(record, category, rank, CANDIDATE_DIR)

    selected_v1, selected_v2, selected_v3 = select_13(results)
    selected_records = []

    print()
    print("=" * 80)
    print("SELECTED 13")
    print("=" * 80)

    for label, selected, score_key in [
        ("v1", selected_v1, "v1_score"),
        ("v2", selected_v2, "v2_score"),
        ("v3", selected_v3, "v3_score"),
    ]:
        target = {"v1": TARGET_V1, "v2": TARGET_V2, "v3": TARGET_V3}[label]
        print(f"\n{label}: {len(selected)} / {target}")
        for rank, record in enumerate(selected, start=1):
            selected_records.append({
                **record,
                "selected_category": label,
                "selected_rank": rank,
            })
            copy_candidate(record, label, rank, SELECTED_DIR)
            print(f"  {label}-{rank}: {record['package']} [score={record[score_key]}]")

    # Selected CSV
    with (REPORT_DIR / "selected_13.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["selected_category", "selected_rank", *CSV_FIELDS]
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for record in selected_records:
            writer.writerow(record)

    # Errors
    errors = [r for r in results if r.get("status") == "ERROR"]
    if errors:
        with (REPORT_DIR / "errors.csv").open("w", newline="", encoding="utf-8") as f:
            fields = ["apk", "filename", "error", "traceback"]
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for error in errors:
                writer.writerow(error)

    successful = [r for r in results if r.get("status") == "OK"]

    print()
    print("=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print(f"APK corpus              : {len(apks)}")
    print(f"Successfully analyzed   : {len(successful)}")
    print(f"Analysis errors         : {len(errors)}")
    print()
    print(f"v1 candidates           : {len(v1)}")
    print(f"v2 candidates           : {len(v2)}")
    print(f"v3 candidates           : {len(v3)}")
    print()
    print(f"Selected v1             : {len(selected_v1)}")
    print(f"Selected v2             : {len(selected_v2)}")
    print(f"Selected v3             : {len(selected_v3)}")
    print(f"Total selected          : {len(selected_records)}")
    print()
    print(f"Reports                 : {REPORT_DIR}")
    print(f"Candidate APKs          : {CANDIDATE_DIR}")
    print(f"Selected APKs           : {SELECTED_DIR}")
    print()
    print("=" * 80)

    if len(selected_records) < 13:
        print("\nWARNING:")
        print("Static analysis did not find enough unique candidates for 5 + 5 + 3.")
        print("Do NOT fill the missing slots arbitrarily.")
        print("Review the candidate CSVs and lower the selection threshold only")
        print("with a documented rationale.")
    else:
        print("\n13 candidates have been copied.")
        print("These are STATIC candidates and must be dynamically validated.")

    print()


if __name__ == "__main__":
    main()