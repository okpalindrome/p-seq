# p-seq

An interactive PCAP sequence-diagram viewer in the browser. Upload a `.pcap` /
`.pcapng` / `.cap`, pick two endpoints, and see their conversation rendered as a
Wireshark-style sequence diagram with pan/zoom, full per-packet details, hex
view, custom labels, and PNG export.

Built around Scapy so it works on any traffic without prior knowledge of the
payload protocol — useful for reverse-engineering proprietary protocols.

---

## Features

- **Scapy-based parser** — extracts L2/L3/L4 plus raw payload bytes as a hex
  dump. Works on any pcap; no protocol dissector required.
- **Display filter bar** with a small Wireshark-inspired DSL: `tcp`, `udp`,
  `ip.addr == 10.0.0.1`, `tcp.port == 80`, `frame.len > 100`,
  `payload contains 474554`, combined with `&&`/`||`/`!`.
- **Interactive sequence diagram** —
  - Two-party view, arrows in true capture-time order across all port pairs.
  - Trackpad pinch zoom, two-finger pan, click-drag pan, double-click reset.
  - Zoom controls (−, +, Fit, 1:1) pinned bottom-right.
  - Click any arrow to inspect.
- **Run collapse** — consecutive identical packets fold into `N×` dots
  (threshold configurable in Settings); click to expand. Labeled packets are
  never collapsed.
- **Per-packet labels** — type a note in the detail panel, it appears in bold
  above the matching arrow (truncated in-diagram, full text in tooltip).
  Persists per-pcap on disk.
- **Wireshark-style packet details panel** — Ethernet / IP / TCP / UDP / Raw
  layers as a collapsible tree with every field, plus an offset / hex / ASCII
  dump of the raw frame.
- **TCP flags** rendered as `[FIN, ACK]`, `[SYN, ACK]`, etc., in bit-position
  order matching Wireshark.
- **Multi-flow indicator** — when two IPs talk over several port pairs at once
  and no port filter is active, the title bar lists the active flows.
- **Show seconds** toggle prefixes each arrow with `+N.NNNs` relative to the
  first rendered packet.
- **Per-pcap history** in the sidebar with delete.
- **PNG export** of the full diagram (natural size, ignores current zoom).
- **B&W theme** — keyboard- and pointer-friendly modals, monospace
  terminal-style aesthetic.
- **Cross-platform** — macOS, Linux, Windows.

---

## Requirements

- Python 3.10+ (developed and tested on 3.11)
- Modern browser (Chrome, Firefox, Safari, Edge)
- No npcap/winpcap needed on Windows — we only *read* pcap files, never
  capture live traffic

---

## Run it

### macOS / Linux

```bash
./run.sh
```

### Windows

```cmd
run.bat
```

Either script creates a `.venv` on first run, installs from `requirements.txt`,
and starts the app on **http://127.0.0.1:5050**.

---

## Using it

1. **Upload pcap** (top-left). The file is parsed once and cached in memory.
2. Click **two endpoints** from the *Parties* list.
3. If multiple port pairs exist between those two IPs, the *Ports* picker
   appears — leave both at `any` to see all flows interleaved by time, or
   pick a specific port pair on either side to focus.
4. Hit **Render diagram**.
5. **Click any arrow** to populate the details panel on the right.
6. Type a note in the **LABEL** field at the top of the details panel and
   press Save (or Enter). The label shows above the arrow.
7. **Settings** (gear icon, top-right) — change the collapse threshold or
   toggle relative-time prefixes.
8. **Export PNG** — saves the full-size diagram with the current labels and
   styling, at 2× pixel ratio.



## Display filter syntax

Supported tokens — case-insensitive for keywords:

```
# protocol shorthands
tcp
udp
icmp

# comparison fields
ip.src      ip.dst      ip.addr        # IPv4/v6 source / destination / either
eth.src     eth.dst     eth.addr       # Ethernet MAC source / destination / either
tcp.port    udp.port                   # any side
tcp.srcport tcp.dstport                # specific direction
udp.srcport udp.dstport
port                                   # any L4 port, any proto
proto                                  # "TCP", "UDP", "ICMP", "IP/<n>", …
frame.len   length                     # frame size in bytes
frame                                  # frame number
info                                   # proto info string
payload                                # payload as a lowercase hex string

# operators
==  !=  >  <  >=  <=  contains
&&  and  ||  or  !  not                # combinators
( … )                                  # grouping
```

Examples:

```
tcp && ip.addr == 10.0.0.1
udp.port == 53 || icmp
frame.len > 1000 && !tcp
payload contains 474554                # "GET" in hex (look for HTTP requests)
ip.src == 192.168.0.10 && tcp.dstport == 22
```

Empty filter = match all packets.

---

## Architecture

```
backend/
  app.py              Flask routes; security middleware; storage
  parser.py           Scapy → packet rows + Wireshark-like layer trees
  filter_expr.py      Custom display-filter tokenizer + parser
  storage/            Uploaded pcaps + per-pcap labels (gitignored)
frontend/
  templates/index.html
  static/css/style.css
  static/js/app.js    Single ~900-line vanilla JS app
requirements.txt
run.sh   run.bat
```

The frontend is plain HTML + CSS + JS with no build step and no external runtime
dependencies. The backend is a single Flask app with no database — pcaps and
labels live on disk under `backend/storage/`.

### State / persistence

| What             | Where                                              |
| ---------------- | -------------------------------------------------- |
| Uploaded pcaps   | `backend/storage/<id>_<filename>`                  |
| Pcap index       | `backend/storage/index.json`                       |
| Per-pcap labels  | `backend/storage/<id>_labels.json`                 |
| Parsed pcap data | In-memory cache (cleared on server restart)        |

### Sequence ordering across multiple flows

When two IPs talk over multiple port pairs (e.g. HTTP and SSH at the same time),
the rendered diagram is **strictly time-ordered** across all port pairs, not
grouped per flow. The `pcap_packets` endpoint sorts by `(epoch, frame)` before
the collapse pass, so even pcaps that aren't in capture order on disk render
correctly.

---

## HTTP API

All paths are under `/api/`. State-changing endpoints (POST, PUT, DELETE)
require a `X-Requested-By: p-seq` header — see **Security model** below.

| Method | Path                                    | Purpose                                |
| ------ | --------------------------------------- | -------------------------------------- |
| POST   | `/api/pcaps`                            | Upload a pcap (multipart, field=`file`)|
| GET    | `/api/pcaps`                            | List pcaps                             |
| DELETE | `/api/pcaps/<id>`                       | Delete pcap + its labels file          |
| GET    | `/api/pcaps/<id>/summary`               | Endpoints + conversations              |
| POST   | `/api/pcaps/<id>/packets`               | Filtered sequence (display filter + parties + collapse) |
| GET    | `/api/pcaps/<id>/packets/<frame>`       | Full packet detail + current label     |
| GET    | `/api/pcaps/<id>/labels`                | All labels for this pcap               |
| PUT    | `/api/pcaps/<id>/labels/<frame>`        | Set / clear label (`{"label": "..."}`) |
| DELETE | `/api/pcaps/<id>/labels/<frame>`        | Remove label                           |

`<id>` is always a 12-hex-character string (`uuid4().hex[:12]`). The server
rejects anything else with HTTP 400.

---

## Environment variables

| Name           | Default       | Effect                                                                  |
| -------------- | ------------- | ----------------------------------------------------------------------- |
| `P_SEQ_HOST`   | `127.0.0.1`   | Bind address. Keep on loopback unless you really mean it.               |
| `P_SEQ_PORT`   | `5050`        | TCP port.                                                               |
| `P_SEQ_DEBUG`  | unset / `0`   | Set to `1` to enable Flask debug mode. **Never enable on a non-local host** — it exposes the Werkzeug interactive debugger, which is RCE if reachable. |

---

## Storage layout (on disk)

```
backend/storage/
├── index.json                          # array of {id, name, filename, …}
├── <id>_<original-filename>.pcap       # the uploaded file
└── <id>_labels.json                    # {"<frame_no>": "user label", …}
```

Deleting a pcap from the History sidebar removes both files. Storage is
gitignored.
