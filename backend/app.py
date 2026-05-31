"""Flask backend for the pcap sequence-diagram viewer."""
from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory, abort
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from backend.parser import parse_pcap, parse_packet_detail
from backend.filter_expr import compile_filter


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
STORAGE = (HERE / "storage").resolve()
INDEX_PATH = STORAGE / "index.json"
FRONTEND = ROOT / "frontend"

STORAGE.mkdir(parents=True, exist_ok=True)
if not INDEX_PATH.exists():
    INDEX_PATH.write_text("[]", encoding="utf-8")


# in-memory cache of parsed pcaps  (id -> parsed dict)
_CACHE: dict[str, dict[str, Any]] = {}

ALLOWED_EXT = {".pcap", ".pcapng", ".cap"}

# Magic bytes that identify pcap / pcapng files. We check these on upload as
# defense in depth — extension allowlist isn't enough since an attacker can
# rename anything to .pcap.
#   libpcap classic: 0xa1b2c3d4 (BE) / 0xd4c3b2a1 (LE)  plus the nanosecond variants
#   pcapng:          Section Header Block magic 0x0a0d0d0a
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Maximum number of bytes we accept in a single user-supplied label.
LABEL_MAX_LEN = 200

# pcap IDs are 12 hex chars (uuid4().hex[:12]). The regex is the source of
# truth — any path or route handler that consumes an ID validates against it.
_VALID_PCAP_ID = re.compile(r"^[0-9a-f]{12}$")

# CSRF defence: every state-changing API request must carry this header.
# Browsers cannot set a custom header on a cross-origin request without a CORS
# preflight, and we never grant CORS preflight, so this is sufficient against
# drive-by POSTs from malicious pages the user happens to visit.
CSRF_HEADER = "X-Requested-By"
CSRF_TOKEN = "p-seq"


app = Flask(
    __name__,
    static_folder=str(FRONTEND / "static"),
    template_folder=str(FRONTEND / "templates"),
)
# Upload size cap. Default 4 GB so multi-gig pcaps load on a workstation; the
# env var lets you raise/lower it without code changes. Note that scapy's
# rdpcap() reads the whole file into memory, so even a 2 GB pcap can need
# ~10 GB of RAM to parse — split big captures with `editcap -c` if you hit OOM.
MAX_UPLOAD_MB = int(os.environ.get("P_SEQ_MAX_UPLOAD_MB", "4096"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


@app.errorhandler(RequestEntityTooLarge)
def _too_large(_e):
    # Without this handler Flask returns its default HTML 413 page, which the
    # JS frontend then chokes on with "Unexpected token '<'…".
    return jsonify(error=f"file too large (max {MAX_UPLOAD_MB} MB; raise P_SEQ_MAX_UPLOAD_MB)"), 413


# ---------- request-level security middleware ----------

@app.before_request
def _csrf_and_id_guard():
    # Block state-changing API calls that lack our custom header.
    if request.path.startswith("/api/") and request.method in (
        "POST", "PUT", "PATCH", "DELETE"
    ):
        if request.headers.get(CSRF_HEADER) != CSRF_TOKEN:
            return jsonify(error="missing or invalid CSRF header"), 403
    # Reject anything that pretends to be a pcap_id but doesn't fit the
    # 12-hex-char shape we issue. This is defense in depth against path
    # traversal even though _safe_storage_path also resolves and re-checks.
    view_args = request.view_args or {}
    pcap_id = view_args.get("pcap_id")
    if pcap_id is not None and not _VALID_PCAP_ID.match(pcap_id):
        return jsonify(error="invalid pcap id"), 400


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


# ---------- index helpers ----------

def _load_index() -> list[dict[str, Any]]:
    try:
        return json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save_index(items: list[dict[str, Any]]) -> None:
    INDEX_PATH.write_text(json.dumps(items, indent=2), encoding="utf-8")


def _get_entry(pcap_id: str) -> dict[str, Any] | None:
    for item in _load_index():
        if item["id"] == pcap_id:
            return item
    return None


def _ensure_parsed(pcap_id: str) -> dict[str, Any]:
    if pcap_id in _CACHE:
        return _CACHE[pcap_id]
    entry = _get_entry(pcap_id)
    if not entry:
        abort(404, description="pcap not found")
    path = _safe_storage_path(entry["filename"])
    if not path.exists():
        abort(404, description="pcap file missing on disk")
    parsed = parse_pcap(str(path))
    _CACHE[pcap_id] = parsed
    return parsed


# ---------- safe filesystem helpers ----------

def _safe_storage_path(name: str) -> Path:
    """Resolve `name` relative to STORAGE and reject anything that escapes.

    Even though all current callers compose `name` from validated IDs, this
    enforces an invariant at the boundary so future changes can't introduce a
    path-traversal bug accidentally.
    """
    candidate = (STORAGE / name).resolve()
    try:
        candidate.relative_to(STORAGE)
    except ValueError:
        raise ValueError(f"path escape: {name!r}")
    return candidate


def _has_pcap_magic(data: bytes) -> bool:
    """True if `data` starts with a known pcap or pcapng magic header."""
    if len(data) < 4:
        return False
    head = data[:4]
    if head in _PCAP_MAGIC:
        return True
    if head == _PCAPNG_MAGIC:
        return True
    return False


def _clean_label(raw: str | None) -> str:
    """Strip control chars and clamp length on a user-supplied label."""
    if not raw:
        return ""
    # Drop ASCII control chars except common whitespace; keep printable Unicode.
    cleaned = "".join(
        ch for ch in raw
        if ch in ("\t", " ") or (ord(ch) >= 0x20 and ord(ch) != 0x7f)
    )
    return cleaned.strip()[:LABEL_MAX_LEN]


# ---------- per-packet label storage ----------

def _labels_path(pcap_id: str) -> Path:
    if not _VALID_PCAP_ID.match(pcap_id):
        raise ValueError("invalid pcap id")
    return _safe_storage_path(f"{pcap_id}_labels.json")


def _load_labels(pcap_id: str) -> dict[str, str]:
    p = _labels_path(pcap_id)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.items() if v}
    except Exception:
        return {}


def _save_labels(pcap_id: str, labels: dict[str, str]) -> None:
    _labels_path(pcap_id).write_text(
        json.dumps(labels, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------- pages ----------

@app.route("/")
def index_html():
    return send_from_directory(str(FRONTEND / "templates"), "index.html")


# ---------- pcap CRUD ----------

@app.post("/api/pcaps")
def upload_pcap():
    if "file" not in request.files:
        return jsonify(error="no file"), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify(error="empty filename"), 400
    name = secure_filename(f.filename)
    if not name:
        return jsonify(error="invalid filename"), 400
    if not any(name.lower().endswith(ext) for ext in ALLOWED_EXT):
        return jsonify(error=f"unsupported extension (allowed: {sorted(ALLOWED_EXT)})"), 400

    # Magic-byte check before we save — don't let .txt files renamed to .pcap
    # land on disk just because the extension lied.
    head = f.stream.read(4)
    f.stream.seek(0)
    if not _has_pcap_magic(head):
        return jsonify(error="not a pcap/pcapng file (bad magic bytes)"), 400

    pcap_id = uuid.uuid4().hex[:12]
    stored_name = f"{pcap_id}_{name}"
    dest = _safe_storage_path(stored_name)
    f.save(str(dest))

    # parse once up front so we know it works and we can cache
    try:
        parsed = parse_pcap(str(dest))
    except Exception as e:
        dest.unlink(missing_ok=True)
        return jsonify(error=f"failed to parse: {e}"), 400

    entry = {
        "id": pcap_id,
        "name": name,
        "filename": stored_name,
        "uploaded_at": time.time(),
        "size_bytes": dest.stat().st_size,
        "packet_count": parsed["total"],
    }
    items = _load_index()
    items.insert(0, entry)
    _save_index(items)
    _CACHE[pcap_id] = parsed
    return jsonify(entry)


@app.get("/api/pcaps")
def list_pcaps():
    return jsonify(_load_index())


@app.delete("/api/pcaps/<pcap_id>")
def delete_pcap(pcap_id: str):
    items = _load_index()
    new_items = [it for it in items if it["id"] != pcap_id]
    if len(new_items) == len(items):
        return jsonify(error="not found"), 404
    # find the file (and its labels file) and delete them
    for it in items:
        if it["id"] == pcap_id:
            try:
                _safe_storage_path(it["filename"]).unlink(missing_ok=True)
            except ValueError:
                pass
            try:
                _labels_path(pcap_id).unlink(missing_ok=True)
            except ValueError:
                pass
    _save_index(new_items)
    _CACHE.pop(pcap_id, None)
    return jsonify(ok=True)


# ---------- pcap inspection ----------

@app.get("/api/pcaps/<pcap_id>/summary")
def pcap_summary(pcap_id: str):
    """Endpoints + conversations + total — used to populate the party selectors."""
    parsed = _ensure_parsed(pcap_id)
    return jsonify({
        "total": parsed["total"],
        "endpoints": parsed["endpoints"],
        "conversations": parsed["conversations"],
    })


@app.post("/api/pcaps/<pcap_id>/packets")
def pcap_packets(pcap_id: str):
    """Return packets filtered by display filter + (optional) src/dst party constraints.

    Body JSON:
      {
        "filter": "tcp && ip.addr == 10.0.0.1",
        "party_a": {"ip": "10.0.0.1", "port": 12345?},
        "party_b": {"ip": "10.0.0.2", "port": 80?},
        "collapse_threshold": 5    (optional, default 5)
      }
    """
    parsed = _ensure_parsed(pcap_id)
    body = request.get_json(silent=True) or {}
    expr = body.get("filter", "")
    try:
        pred = compile_filter(expr)
    except Exception as e:
        return jsonify(error=f"bad filter: {e}"), 400

    party_a = body.get("party_a") or {}
    party_b = body.get("party_b") or {}
    a_ip = party_a.get("ip")
    b_ip = party_b.get("ip")
    a_port = party_a.get("port")
    b_port = party_b.get("port")
    threshold = int(body.get("collapse_threshold", 5))

    def party_match(pkt: dict[str, Any]) -> bool:
        if not (a_ip and b_ip):
            return True
        s, d = pkt.get("src_ip"), pkt.get("dst_ip")
        sp, dp = pkt.get("src_port"), pkt.get("dst_port")
        ok_a_to_b = s == a_ip and d == b_ip
        ok_b_to_a = s == b_ip and d == a_ip
        if not (ok_a_to_b or ok_b_to_a):
            return False
        if a_port is not None:
            if ok_a_to_b and sp != a_port:
                return False
            if ok_b_to_a and dp != a_port:
                return False
        if b_port is not None:
            if ok_a_to_b and dp != b_port:
                return False
            if ok_b_to_a and sp != b_port:
                return False
        return True

    # Strict capture-time ordering: across multiple port pairs between the same
    # two IPs, we interleave packets by epoch (then frame as tiebreaker) so the
    # sequence diagram reflects real send/receive order regardless of which port
    # each packet is on.
    matched_raw = sorted(
        (p for p in parsed["packets"] if pred(p) and party_match(p)),
        key=lambda p: (p.get("epoch") or 0, p.get("frame") or 0),
    )

    # Attach the current label (if any) to each matched packet. Labels also
    # participate in the collapse signature so a labeled packet always stays
    # as its own visible arrow on the diagram.
    labels = _load_labels(pcap_id)
    matched = []
    for p in matched_raw:
        q = dict(p)
        q["label"] = labels.get(str(p["frame"]), "")
        matched.append(q)

    # Distinct port pairs present in the matched set (for the UI title hint).
    port_pairs: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for p in matched:
        sp, dp = p.get("src_port"), p.get("dst_port")
        if sp is None or dp is None:
            continue
        # canonical ordering: (a-side port, b-side port)
        if p.get("src_ip") == a_ip:
            key = (sp, dp, p.get("proto"))
        else:
            key = (dp, sp, p.get("proto"))
        if key in seen:
            continue
        seen.add(key)
        port_pairs.append({"a_port": key[0], "b_port": key[1], "proto": key[2]})

    # collapse runs of identical successive packets (same src/dst/ports/payload_hex/label)
    sequence: list[dict[str, Any]] = []
    i = 0
    while i < len(matched):
        run = [matched[i]]
        j = i + 1
        sig = (
            matched[i].get("src_ip"), matched[i].get("dst_ip"),
            matched[i].get("src_port"), matched[i].get("dst_port"),
            matched[i].get("proto"), matched[i].get("payload_hex"),
            matched[i].get("info"), matched[i].get("label", ""),
        )
        while j < len(matched):
            jsig = (
                matched[j].get("src_ip"), matched[j].get("dst_ip"),
                matched[j].get("src_port"), matched[j].get("dst_port"),
                matched[j].get("proto"), matched[j].get("payload_hex"),
                matched[j].get("info"), matched[j].get("label", ""),
            )
            if jsig == sig:
                run.append(matched[j])
                j += 1
            else:
                break

        if len(run) >= threshold:
            sequence.append({
                "kind": "collapsed",
                "count": len(run),
                "first_frame": run[0]["frame"],
                "last_frame": run[-1]["frame"],
                "epoch": run[0]["epoch"],
                "epoch_last": run[-1]["epoch"],
                "src_ip": run[0]["src_ip"],
                "dst_ip": run[0]["dst_ip"],
                "src_port": run[0]["src_port"],
                "dst_port": run[0]["dst_port"],
                "proto": run[0]["proto"],
                "info": run[0]["info"],
                "frames": [p["frame"] for p in run],
                "epochs": [p["epoch"] for p in run],
            })
        else:
            for p in run:
                sequence.append({"kind": "packet", **p})
        i = j

    return jsonify({
        "matched": len(matched),
        "total": parsed["total"],
        "sequence": sequence,
        "port_pairs": port_pairs,
    })


@app.get("/api/pcaps/<pcap_id>/packets/<int:frame_no>")
def pcap_packet_detail(pcap_id: str, frame_no: int):
    entry = _get_entry(pcap_id)
    if not entry:
        return jsonify(error="not found"), 404
    if frame_no < 1 or frame_no > 10_000_000:
        return jsonify(error="frame out of range"), 400
    path = _safe_storage_path(entry["filename"])
    try:
        detail = parse_packet_detail(str(path), frame_no)
    except Exception as e:
        return jsonify(error=f"failed to parse frame: {e}"), 500
    if detail is None:
        return jsonify(error="frame out of range"), 404
    detail["label"] = _load_labels(pcap_id).get(str(frame_no), "")
    return jsonify(detail)


# ---------- per-packet labels CRUD ----------

@app.get("/api/pcaps/<pcap_id>/labels")
def list_labels(pcap_id: str):
    if not _get_entry(pcap_id):
        return jsonify(error="not found"), 404
    return jsonify(_load_labels(pcap_id))


@app.put("/api/pcaps/<pcap_id>/labels/<int:frame_no>")
def set_label(pcap_id: str, frame_no: int):
    if not _get_entry(pcap_id):
        return jsonify(error="not found"), 404
    if frame_no < 1 or frame_no > 10_000_000:
        return jsonify(error="invalid frame"), 400
    body = request.get_json(silent=True) or {}
    label = _clean_label(body.get("label"))
    labels = _load_labels(pcap_id)
    if label:
        labels[str(frame_no)] = label
    else:
        labels.pop(str(frame_no), None)
    _save_labels(pcap_id, labels)
    return jsonify(ok=True, frame=frame_no, label=label)


@app.delete("/api/pcaps/<pcap_id>/labels/<int:frame_no>")
def delete_label(pcap_id: str, frame_no: int):
    if not _get_entry(pcap_id):
        return jsonify(error="not found"), 404
    labels = _load_labels(pcap_id)
    labels.pop(str(frame_no), None)
    _save_labels(pcap_id, labels)
    return jsonify(ok=True)


# ---------- entry point ----------

if __name__ == "__main__":
    # debug is OFF by default: enabling it exposes the Werkzeug interactive
    # debugger on error pages, which is remote code execution if the server
    # is reachable from anywhere but the developer's machine.
    debug = os.environ.get("P_SEQ_DEBUG") == "1"
    host = os.environ.get("P_SEQ_HOST", "127.0.0.1")
    port = int(os.environ.get("P_SEQ_PORT", "5050"))
    app.run(host=host, port=port, debug=debug)
