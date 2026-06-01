// p-seq frontend
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const SVG_NS = "http://www.w3.org/2000/svg";

  // ---------- state ----------
  const state = {
    currentPcap: null,        // id
    summary: null,            // {endpoints, conversations, total}
    selected: [],             // up to 2 ip strings
    portChoice: { a: null, b: null }, // chosen port per side
    sequence: [],             // current rendered sequence
    expandedCollapsed: new Set(), // first_frame of collapsed runs that user expanded
    selectedKey: null,        // for highlighting the currently-clicked item
    view: { scale: 1, tx: 0, ty: 0 },  // diagram viewport transform
    contentBounds: { w: 0, h: 0 },     // natural content size
    labels: {},               // frame_no(str) -> user label
    hidden: new Set(),        // frame_no(int) — user-hidden frames (rendered as dots)
    settings: {
      collapseThreshold: 5,
      showSeconds: false,
    },
  };

  // ---------- helpers ----------
  // Every state-changing request carries this header. The server rejects POST/
  // PUT/DELETE/PATCH on /api/ without it (CSRF defence — cross-origin browser
  // requests can't add a custom header without a preflight, and we don't grant
  // CORS preflight).
  const CSRF_HEADERS = { "X-Requested-By": "p-seq" };

  // Read a response that's expected to be JSON. If the server returned an
  // error page (HTML), we surface the status code instead of crashing on the
  // JSON parse — this matters for things like the 413 "too large" page that
  // Flask serves before our handler can intercept on edge cases.
  async function jsonOrThrow(r, fallback) {
    if (r.ok) return r.json();
    let msg = `${fallback} (HTTP ${r.status})`;
    try {
      const text = await r.text();
      try {
        const j = JSON.parse(text);
        if (j && j.error) msg = j.error;
      } catch { /* not JSON — keep the HTTP-status message */ }
    } catch { /* unreadable body — keep generic */ }
    throw new Error(msg);
  }

  // XHR-based upload — fetch() doesn't give upload progress events without the
  // streams API. `onUploadPct(fraction)` is called continuously during the
  // network upload; `onParsing()` fires once the bytes are fully on the wire
  // and the server begins parsing (response not yet received).
  function uploadWithProgress(file, onUploadPct, onParsing) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      const fd = new FormData();
      fd.append("file", file);
      xhr.open("POST", "/api/pcaps");
      xhr.setRequestHeader("X-Requested-By", "p-seq");
      xhr.upload.addEventListener("progress", (e) => {
        if (e.lengthComputable) onUploadPct(e.loaded / e.total);
      });
      xhr.upload.addEventListener("load", () => {
        onUploadPct(1);
        onParsing();
      });
      xhr.addEventListener("load", () => {
        const text = xhr.responseText;
        if (xhr.status >= 200 && xhr.status < 300) {
          try { resolve(JSON.parse(text)); }
          catch { reject(new Error("upload failed: response was not JSON")); }
        } else {
          let msg = `upload failed (HTTP ${xhr.status})`;
          try { msg = JSON.parse(text).error || msg; } catch {}
          reject(new Error(msg));
        }
      });
      xhr.addEventListener("error", () => reject(new Error("upload network error")));
      xhr.addEventListener("abort", () => reject(new Error("upload aborted")));
      xhr.send(fd);
    });
  }

  const api = {
    async list() { return (await fetch("/api/pcaps")).json(); },
    async upload(file, onUploadPct, onParsing) {
      return uploadWithProgress(file, onUploadPct, onParsing);
    },
    async del(id) {
      const r = await fetch(`/api/pcaps/${id}`, {
        method: "DELETE",
        headers: { ...CSRF_HEADERS },
      });
      if (!r.ok) throw new Error("delete failed");
    },
    async summary(id) {
      const r = await fetch(`/api/pcaps/${id}/summary`);
      if (!r.ok) throw new Error("summary failed");
      return r.json();
    },
    async packets(id, body) {
      const r = await fetch(`/api/pcaps/${id}/packets`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...CSRF_HEADERS },
        body: JSON.stringify(body),
      });
      return jsonOrThrow(r, "packets failed");
    },
    async detail(id, frame) {
      const r = await fetch(`/api/pcaps/${id}/packets/${frame}`);
      if (!r.ok) throw new Error("detail failed");
      return r.json();
    },
    async getLabels(id) {
      const r = await fetch(`/api/pcaps/${id}/labels`);
      if (!r.ok) return {};
      return r.json();
    },
    async setLabel(id, frame, label) {
      const r = await fetch(`/api/pcaps/${id}/labels/${frame}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", ...CSRF_HEADERS },
        body: JSON.stringify({ label }),
      });
      if (!r.ok) throw new Error("save label failed");
      return r.json();
    },
    async getHidden(id) {
      const r = await fetch(`/api/pcaps/${id}/hidden`);
      if (!r.ok) return [];
      return r.json();
    },
    async hide(id, frame) {
      const r = await fetch(`/api/pcaps/${id}/hidden/${frame}`, {
        method: "PUT", headers: { ...CSRF_HEADERS },
      });
      if (!r.ok) throw new Error("hide failed");
      return r.json();
    },
    async unhide(id, frame) {
      const r = await fetch(`/api/pcaps/${id}/hidden/${frame}`, {
        method: "DELETE", headers: { ...CSRF_HEADERS },
      });
      if (!r.ok) throw new Error("unhide failed");
      return r.json();
    },
    async batchHidden(id, action, frames) {
      const r = await fetch(`/api/pcaps/${id}/hidden:batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...CSRF_HEADERS },
        body: JSON.stringify({ action, frames }),
      });
      if (!r.ok) throw new Error("batch hide failed");
      return r.json();
    },
  };

  const escapeHTML = (s) => String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const fmtBytes = (n) => {
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 ** 2).toFixed(1)} MB`;
  };

  const fmtTime = (iso) => {
    try {
      const d = new Date(iso);
      return d.toISOString().replace("T", " ").replace("Z", "");
    } catch { return iso; }
  };

  // ---------- history ----------
  async function refreshHistory() {
    const items = await api.list();
    const ul = $("historyList");
    ul.innerHTML = "";
    if (!items.length) {
      ul.innerHTML = '<li class="muted small" style="border:none;cursor:default">No pcaps yet</li>';
      return;
    }
    for (const it of items) {
      const li = document.createElement("li");
      if (it.id === state.currentPcap) li.classList.add("active");
      li.innerHTML = `
        <div>
          <div>${escapeHTML(it.name)}</div>
          <div class="meta">${it.packet_count} pkts · ${fmtBytes(it.size_bytes)}</div>
        </div>
        <button class="del" title="Delete">×</button>
      `;
      li.addEventListener("click", (e) => {
        if (e.target.classList.contains("del")) return;
        selectPcap(it.id);
      });
      li.querySelector(".del").addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!confirm(`Delete ${it.name} from history?`)) return;
        await api.del(it.id);
        if (state.currentPcap === it.id) {
          state.currentPcap = null;
          state.summary = null;
          state.selected = [];
          state.sequence = [];
          renderEndpoints();
          renderDiagram();
        }
        refreshHistory();
      });
      ul.appendChild(li);
    }
  }

  async function selectPcap(id) {
    state.currentPcap = id;
    state.selected = [];
    state.portChoice = { a: null, b: null };
    state.sequence = [];
    state.labels = {};
    state.hidden = new Set();
    const [summary, labels, hidden] = await Promise.all([
      api.summary(id), api.getLabels(id), api.getHidden(id),
    ]);
    state.summary = summary;
    state.labels = labels || {};
    state.hidden = new Set(hidden || []);
    refreshHistory();
    renderEndpoints();
    renderPortPicker();
    renderDiagram();
    setDiagramTitle();
    closeDetail();
  }

  // ---------- endpoints / ports ----------
  function renderEndpoints() {
    const ul = $("endpointList");
    ul.innerHTML = "";
    if (!state.summary) {
      ul.innerHTML = '<li class="muted small" style="border:none;cursor:default">Load a pcap to see endpoints</li>';
      $("renderBtn").disabled = true;
      return;
    }
    for (const ep of state.summary.endpoints) {
      const li = document.createElement("li");
      const idx = state.selected.indexOf(ep.ip);
      if (idx >= 0) li.classList.add("selected");
      const role = idx === 0 ? "A" : idx === 1 ? "B" : "";
      const mac = ep.mac ? ` · ${ep.mac}` : "";
      li.innerHTML = `
        ${role ? `<span class="role">${role}</span>` : ""}
        <div>${escapeHTML(ep.ip)}</div>
        <div class="muted small">${ep.packets} pkts${escapeHTML(mac)}</div>
      `;
      li.addEventListener("click", () => toggleEndpoint(ep.ip));
      ul.appendChild(li);
    }
    $("renderBtn").disabled = state.selected.length !== 2;
  }

  function toggleEndpoint(ip) {
    const i = state.selected.indexOf(ip);
    if (i >= 0) {
      state.selected.splice(i, 1);
    } else {
      if (state.selected.length >= 2) state.selected.shift();
      state.selected.push(ip);
    }
    state.portChoice = { a: null, b: null };
    renderEndpoints();
    renderPortPicker();
  }

  function conversationFor(aIp, bIp) {
    if (!state.summary) return null;
    return state.summary.conversations.find(
      (c) => (c.a === aIp && c.b === bIp) || (c.a === bIp && c.b === aIp)
    );
  }

  function renderPortPicker() {
    const box = $("portPicker");
    const body = $("portPickerBody");
    body.innerHTML = "";
    if (state.selected.length !== 2) { box.classList.add("hidden"); return; }
    const [aIp, bIp] = state.selected;
    const convo = conversationFor(aIp, bIp);
    if (!convo || convo.ports.length === 0) { box.classList.add("hidden"); return; }

    // ports in convo are stored as (a_port, b_port) with a=sorted-first.
    // Normalise to (aIp side port, bIp side port).
    const flipped = convo.a !== aIp;
    const pairs = convo.ports.map(p => ({
      aPort: flipped ? p.b_port : p.a_port,
      bPort: flipped ? p.a_port : p.b_port,
      proto: p.proto,
    }));
    // Distinct ports per side
    const aPorts = [...new Set(pairs.map(p => `${p.aPort}/${p.proto}`))];
    const bPorts = [...new Set(pairs.map(p => `${p.bPort}/${p.proto}`))];

    // Only show pickers if there's more than 1 option per side
    if (aPorts.length <= 1 && bPorts.length <= 1) {
      box.classList.add("hidden");
      return;
    }
    box.classList.remove("hidden");

    const makeRow = (label, opts, side) => {
      const wrap = document.createElement("div");
      wrap.className = "port-row";
      const optsHtml = ['<option value="">any</option>',
        ...opts.map(o => `<option value="${escapeHTML(o)}">${escapeHTML(o)}</option>`)].join("");
      wrap.innerHTML = `<label>${escapeHTML(label)}</label><select>${optsHtml}</select>`;
      wrap.querySelector("select").addEventListener("change", (e) => {
        const v = e.target.value;
        const portNum = v ? parseInt(v.split("/")[0], 10) : null;
        state.portChoice[side] = portNum;
      });
      return wrap;
    };
    body.appendChild(makeRow(`${aIp} port`, aPorts, "a"));
    body.appendChild(makeRow(`${bIp} port`, bPorts, "b"));
  }

  // ---------- render progress UI ----------
  // Mirrors uploadUI: the "Render diagram" button slot is taken over by an
  // indeterminate-bar + elapsed-time card while a packets request is in
  // flight. The Apply button on the topbar also shows a busy state so the
  // user gets feedback regardless of which button they pressed.
  const renderUI = {
    timer: null,
    start: 0,
    origApplyText: null,
    busy(stage, meta) {
      this._clearTimer();
      $("renderBtn").classList.add("hidden");
      $("renderProgress").classList.remove("hidden");
      $("renderStage").textContent = stage;
      $("renderMeta").textContent = meta || "";
      const apply = $("applyFilter");
      if (apply) {
        if (this.origApplyText === null) this.origApplyText = apply.textContent;
        apply.textContent = "…";
        apply.disabled = true;
      }
      $("matchCount").textContent = "processing…";
      this.start = Date.now();
      const tick = () => {
        const elapsed = (Date.now() - this.start) / 1000;
        $("renderElapsed").textContent = `${elapsed.toFixed(1)}s`;
      };
      tick();
      this.timer = setInterval(tick, 200);
    },
    update(stage, meta) {
      $("renderStage").textContent = stage;
      if (meta !== undefined) $("renderMeta").textContent = meta;
    },
    idle() {
      this._clearTimer();
      $("renderProgress").classList.add("hidden");
      $("renderBtn").classList.remove("hidden");
      const apply = $("applyFilter");
      if (apply) {
        if (this.origApplyText !== null) apply.textContent = this.origApplyText;
        apply.disabled = false;
      }
      this.origApplyText = null;
    },
    _clearTimer() {
      if (this.timer) { clearInterval(this.timer); this.timer = null; }
    },
  };

  // ---------- packet fetch + diagram ----------
  async function renderRequested() {
    if (state.selected.length !== 2 || !state.currentPcap) return;
    const [aIp, bIp] = state.selected;
    const body = {
      filter: $("filter").value,
      party_a: { ip: aIp, port: state.portChoice.a },
      party_b: { ip: bIp, port: state.portChoice.b },
      collapse_threshold: state.settings.collapseThreshold,
    };
    const filterDesc = $("filter").value.trim();
    renderUI.busy(
      "Filtering",
      `${aIp} ↔ ${bIp}${filterDesc ? `   ·   ${filterDesc}` : ""}`,
    );
    try {
      const res = await api.packets(state.currentPcap, body);
      state.sequence = res.sequence;
      state.activePortPairs = res.port_pairs || [];
      state.expandedCollapsed = new Set();
      state.view = { scale: 1, tx: 0, ty: 0 };
      $("matchCount").textContent = `${res.matched} / ${res.total} matched`;
      // Stage transition: response is back, now we draw. For small renders
      // this is invisible; for huge ones the user sees "Drawing" briefly.
      renderUI.update("Drawing", `${res.matched} matched`);
      // yield to the browser so the stage label paints before drawDiagram blocks
      await new Promise((r) => requestAnimationFrame(r));
      renderDiagram();
      setDiagramTitle();
    } catch (e) {
      alert(e.message);
    } finally {
      renderUI.idle();
    }
  }

  function setDiagramTitle() {
    if (state.selected.length !== 2) {
      $("diagramTitle").textContent = "No diagram yet — upload a pcap and pick two parties.";
      syncHeaderHeights();
      return;
    }
    const [a, b] = state.selected;
    const pa = state.portChoice.a ? `:${state.portChoice.a}` : "";
    const pb = state.portChoice.b ? `:${state.portChoice.b}` : "";
    const head = `${a}${pa}  ↔  ${b}${pb}`;
    const pairs = state.activePortPairs || [];
    if (pairs.length > 1) {
      const list = pairs
        .map(p => `${p.a_port}↔${p.b_port}/${p.proto}`)
        .join(", ");
      $("diagramTitle").textContent = `${head}   ·   ${pairs.length} flows interleaved by time: ${list}`;
    } else {
      $("diagramTitle").textContent = head;
    }
    syncHeaderHeights();
  }

  // When the diagram title wraps (long port-pair lists, narrow window) it
  // grows beyond the default 34px. Force the right-pane "Packet details"
  // header to grow too so the two horizontal border lines still line up.
  function syncHeaderHeights() {
    const dt = document.querySelector(".diagram-title");
    const dh = document.querySelector(".detail-header");
    if (!dt || !dh) return;
    dh.style.minHeight = dt.offsetHeight + "px";
  }

  // SVG rendering
  function svgEl(name, attrs = {}, parent = null) {
    const el = document.createElementNS(SVG_NS, name);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    if (parent) parent.appendChild(el);
    return el;
  }

  function renderDiagram() {
    const svg = $("diagram");
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    const wrap = document.querySelector(".diagram-wrap");
    const vw = Math.max(400, wrap.clientWidth);
    const vh = Math.max(300, wrap.clientHeight);
    // SVG viewBox = visible pixel coords. Viewport <g> handles pan/zoom.
    svg.setAttribute("viewBox", `0 0 ${vw} ${vh}`);
    svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
    svg.removeAttribute("width");
    svg.removeAttribute("height");

    const viewG = svgEl("g", { id: "diagramViewport" }, svg);

    if (state.selected.length !== 2 || state.sequence.length === 0) {
      const t = svgEl("text", {
        x: vw / 2, y: vh / 2, "text-anchor": "middle",
        "font-family": "monospace", "font-size": 13, fill: "#666"
      }, viewG);
      t.textContent = state.selected.length !== 2
        ? "Select two parties from the left, then press Render diagram."
        : "No packets matched. Adjust the filter.";
      state.contentBounds = { w: vw, h: vh };
      applyView();
      return;
    }

    const [aIp, bIp] = state.selected;

    // Build expanded display list
    const items = [];
    for (const item of state.sequence) {
      if (item.kind === "collapsed" && state.expandedCollapsed.has(item.first_frame)) {
        // Header row above the expanded run gives the user a way back —
        // clicking it re-folds the run into the dots cluster.
        items.push({
          kind: "expanded-header",
          first_frame: item.first_frame,
          last_frame: item.last_frame,
          count: item.frames.length,
        });
        for (let i = 0; i < item.frames.length; i++) {
          items.push({
            kind: "packet",
            frame: item.frames[i],
            epoch: (item.epochs && item.epochs[i]) ?? item.epoch,
            src_ip: item.src_ip, dst_ip: item.dst_ip,
            src_port: item.src_port, dst_port: item.dst_port,
            proto: item.proto, info: `${item.info}  (${i + 1}/${item.frames.length})`,
          });
        }
      } else {
        items.push(item);
      }
    }

    // Content layout in natural coordinates (independent of viewport size)
    const W = Math.max(900, vw);
    const rowH = 50;
    const headerH = 80;
    const footerH = 40;
    const xA = Math.floor(W * 0.28);
    const xB = Math.floor(W * 0.72);
    const H = headerH + items.length * rowH + footerH;
    state.contentBounds = { w: W, h: H };

    // First epoch in the rendered set, for relative-time labels.
    let firstEpoch = null;
    for (const it of items) {
      const e = it.epoch;
      if (typeof e === "number") { firstEpoch = e; break; }
    }
    state.firstEpoch = firstEpoch;

    const pa = state.portChoice.a ? `:${state.portChoice.a}` : "";
    const pb = state.portChoice.b ? `:${state.portChoice.b}` : "";
    const macA = (state.summary.endpoints.find(e => e.ip === aIp) || {}).mac || "";
    const macB = (state.summary.endpoints.find(e => e.ip === bIp) || {}).mac || "";

    drawPartyHeader(viewG, xA, 10, `${aIp}${pa}`, macA);
    drawPartyHeader(viewG, xB, 10, `${bIp}${pb}`, macB);

    svgEl("line", { x1: xA, y1: headerH - 10, x2: xA, y2: H - footerH / 2, class: "lifeline" }, viewG);
    svgEl("line", { x1: xB, y1: headerH - 10, x2: xB, y2: H - footerH / 2, class: "lifeline" }, viewG);

    let y = headerH;
    items.forEach((it) => {
      const cy = y + rowH / 2;
      if (it.kind === "packet") {
        const fromA = it.src_ip === aIp;
        const x1 = fromA ? xA : xB;
        const x2 = fromA ? xB : xA;
        drawArrow(viewG, x1, x2, cy, it);
      } else if (it.kind === "collapsed") {
        const fromA = it.src_ip === aIp;
        const x1 = fromA ? xA : xB;
        const x2 = fromA ? xB : xA;
        drawCollapsed(viewG, x1, x2, cy, it);
      } else if (it.kind === "hidden") {
        drawHidden(viewG, xA, xB, cy, it);
      } else if (it.kind === "expanded-header") {
        drawExpandedHeader(viewG, xA, xB, cy, it);
      }
      y += rowH;
    });

    applyView();
    if (state.selectedKey != null) highlightSelected();
  }

  function drawPartyHeader(svg, cx, y, label, sub) {
    const w = 220, h = 50;
    const x = cx - w / 2;
    svgEl("rect", { x, y, width: w, height: h, class: "party-box" }, svg);
    const t = svgEl("text", { x: cx, y: y + 22, "text-anchor": "middle", class: "party-label" }, svg);
    t.textContent = label;
    if (sub) {
      const s = svgEl("text", { x: cx, y: y + 38, "text-anchor": "middle", class: "party-sub" }, svg);
      s.textContent = sub;
    }
  }

  function fmtRelSecs(epoch) {
    if (state.firstEpoch == null || typeof epoch !== "number") return "";
    const dt = epoch - state.firstEpoch;
    const sign = dt < 0 ? "-" : "+";
    return `${sign}${Math.abs(dt).toFixed(3)}s`;
  }

  function arrowLabel(it) {
    const parts = [];
    if (state.settings.showSeconds) {
      const sec = fmtRelSecs(it.epoch);
      if (sec) parts.push(sec);
    }
    parts.push(`#${it.frame}`, it.proto || "", it.info || "");
    return parts.filter(Boolean).join("  ").slice(0, 110);
  }

  const CUSTOM_LABEL_MAX = 38;

  function drawArrow(svg, x1, x2, y, it) {
    const key = `pkt:${it.frame}`;
    const dir = x2 > x1 ? 1 : -1;
    const pad = 8;
    const fromX = x1 + dir * pad;
    const toX = x2 - dir * pad;

    const hit = svgEl("line", {
      x1: fromX, y1: y, x2: toX, y2: y,
      class: "arrow-hit", "data-key": key,
    }, svg);
    const line = svgEl("line", {
      x1: fromX, y1: y, x2: toX, y2: y,
      class: "arrow", "data-key": key,
    }, svg);
    const hx = toX, hy = y;
    const triBack = hx - dir * 10;
    const tri = svgEl("polygon", {
      points: `${hx},${hy} ${triBack},${hy - 5} ${triBack},${hy + 5}`,
      class: "arrow-head", "data-key": key,
    }, svg);
    const cx = (fromX + toX) / 2;
    const lbl = svgEl("text", {
      x: cx, y: y - 6, "text-anchor": "middle", class: "arrow-label", "data-key": key,
    }, svg);
    lbl.textContent = arrowLabel(it);

    const handler = () => selectPacket(it.frame, key);
    const handlers = [hit, line, tri, lbl];

    // Custom user label (shown above the auto info line, truncated for the
    // diagram; <title> carries the full text for the browser tooltip).
    const custom = it.label || state.labels[it.frame] || "";
    if (custom) {
      const short = custom.length > CUSTOM_LABEL_MAX
        ? custom.slice(0, CUSTOM_LABEL_MAX - 1) + "…"
        : custom;
      const customLbl = svgEl("text", {
        x: cx, y: y - 20, "text-anchor": "middle",
        class: "arrow-custom-label", "data-key": key,
      }, svg);
      customLbl.textContent = short;
      const t = svgEl("title", {}, customLbl);
      t.textContent = custom;
      handlers.push(customLbl);
    }

    for (const el of handlers) el.addEventListener("click", handler);
  }

  // Header above an expanded auto-collapsed run — clicking re-folds the run
  // back into a single dots pill so the user can compact noise after peeking.
  function drawExpandedHeader(svg, xA, xB, y, it) {
    const key = `exp:${it.first_frame}`;
    const cx = (xA + xB) / 2;
    const text = `▴ ${it.count}× #${it.first_frame}–${it.last_frame}  ·  click to collapse`;
    const w = pillWidthFor(text, 180);

    svgEl("line", {
      x1: xA + 8, y1: y, x2: cx - w / 2, y2: y,
      class: "arrow", "stroke-dasharray": "3 4", "data-key": key,
    }, svg);
    svgEl("line", {
      x1: cx + w / 2, y1: y, x2: xB - 8, y2: y,
      class: "arrow", "stroke-dasharray": "3 4", "data-key": key,
    }, svg);
    svgEl("rect", {
      x: cx - w / 2, y: y - 11, width: w, height: 22,
      class: "collapse-bg", "data-key": key,
    }, svg);
    const lbl = svgEl("text", {
      x: cx, y: y + 4, "text-anchor": "middle", class: "collapse-label", "data-key": key,
    }, svg);
    lbl.textContent = text;

    const handler = () => {
      state.expandedCollapsed.delete(it.first_frame);
      renderDiagram();
    };
    svg.querySelectorAll(`[data-key="${key}"]`).forEach((el) => el.addEventListener("click", handler));
  }

  // User-hidden run: dashed line + 3 ghost dots + "N hidden" pill. Span both
  // lifelines because a hidden run may contain packets going in both
  // directions; we just communicate "stuff happened here, click to bring it
  // back". Clicking the cluster unhides every frame it represents.
  function drawHidden(svg, xA, xB, y, it) {
    const key = `hid:${it.first_frame}`;
    const cx = (xA + xB) / 2;
    const hText = `${it.count} hidden — click to show`;
    const cw = pillWidthFor(hText, 150);

    // dashed line from each lifeline up to the pill
    svgEl("line", {
      x1: xA + 8, y1: y, x2: cx - cw / 2, y2: y,
      class: "hidden-line", "data-key": key,
    }, svg);
    svgEl("line", {
      x1: cx + cw / 2, y1: y, x2: xB - 8, y2: y,
      class: "hidden-line", "data-key": key,
    }, svg);

    const rect = svgEl("rect", {
      x: cx - cw / 2, y: y - 11, width: cw, height: 22,
      class: "hidden-bg", "data-key": key,
    }, svg);
    const g = svgEl("g", { class: "hidden-dots", "data-key": key }, svg);
    [-14, 0, 14].forEach((dx) => svgEl("circle", { cx: cx + dx, cy: y - 3, r: 1.8 }, g));
    const lbl = svgEl("text", {
      x: cx, y: y + 7, "text-anchor": "middle", class: "hidden-label", "data-key": key,
    }, svg);
    lbl.textContent = hText;
    const titleEl = svgEl("title", {}, lbl);
    titleEl.textContent = `Hidden frames: ${it.frames.join(", ")}`;

    const handler = async () => {
      try {
        await api.batchHidden(state.currentPcap, "remove", it.frames);
        for (const f of it.frames) state.hidden.delete(f);
        renderRequested();
      } catch (e) { alert(e.message); }
    };
    for (const el of [rect, g, lbl, ...svg.querySelectorAll(`[data-key="${key}"]`)]) {
      el.addEventListener("click", handler);
    }
  }

  // Rough monospace pixel-width at 10 px font (used to size the pills around
  // collapse/hidden labels so the text never spills outside the border).
  const MONO_CHAR_PX = 6.5;
  const pillWidthFor = (text, minPx) => Math.max(minPx, Math.ceil(text.length * MONO_CHAR_PX + 24));

  function drawCollapsed(svg, x1, x2, y, it) {
    const key = `col:${it.first_frame}`;
    const dir = x2 > x1 ? 1 : -1;
    const pad = 8;
    const fromX = x1 + dir * pad;
    const toX = x2 - dir * pad;
    const cx = (fromX + toX) / 2;

    // Compute label text up front so we can size the pill to fit.
    let cText = `${it.count}× #${it.first_frame}–${it.last_frame}`;
    if (state.settings.showSeconds && typeof it.epoch === "number") {
      const a = fmtRelSecs(it.epoch);
      const b = fmtRelSecs(it.epoch_last);
      if (a && b) cText = `${a}→${b}  ${cText}`;
    }
    cText += "  (click to expand)";
    const w = pillWidthFor(cText, 150);
    const h = 22;

    // dotted line (broken around the pill so the line doesn't pass under it)
    svgEl("line", {
      x1: fromX, y1: y, x2: cx - w / 2, y2: y,
      class: "arrow", "stroke-dasharray": "3 4", "data-key": key,
    }, svg);
    svgEl("line", {
      x1: cx + w / 2, y1: y, x2: toX, y2: y,
      class: "arrow", "stroke-dasharray": "3 4", "data-key": key,
    }, svg);

    // arrow head
    const hx = toX, hy = y;
    const triBack = hx - dir * 10;
    svgEl("polygon", {
      points: `${hx},${hy} ${triBack},${hy - 5} ${triBack},${hy + 5}`,
      class: "arrow-head", "data-key": key,
    }, svg);

    // pill background + dots cluster + label
    svgEl("rect", {
      x: cx - w / 2, y: y - h / 2, width: w, height: h,
      class: "collapse-bg", "data-key": key,
    }, svg);
    const g = svgEl("g", { class: "collapse-dots", "data-key": key }, svg);
    [-12, 0, 12].forEach((dx) => svgEl("circle", { cx: cx + dx, cy: y - 4, r: 2 }, g));
    const lbl = svgEl("text", {
      x: cx, y: y + 7, "text-anchor": "middle", class: "collapse-label", "data-key": key,
    }, svg);
    lbl.textContent = cText;

    const handler = () => {
      state.expandedCollapsed.add(it.first_frame);
      renderDiagram();
    };
    svg.querySelectorAll(`[data-key="${key}"]`).forEach(el => el.addEventListener("click", handler));
  }

  // ---------- pan / zoom ----------
  function applyView() {
    const g = document.getElementById("diagramViewport");
    if (!g) return;
    g.setAttribute(
      "transform",
      `translate(${state.view.tx} ${state.view.ty}) scale(${state.view.scale})`
    );
    const z = $("zoomLevel");
    if (z) z.textContent = `${Math.round(state.view.scale * 100)}%`;
  }

  function resetView() {
    state.view = { scale: 1, tx: 0, ty: 0 };
    applyView();
  }

  function fitView() {
    const wrap = document.querySelector(".diagram-wrap");
    const { w, h } = state.contentBounds;
    if (!w || !h) return;
    const pad = 20;
    const sx = (wrap.clientWidth - pad * 2) / w;
    const sy = (wrap.clientHeight - pad * 2) / h;
    const s = Math.min(sx, sy, 1);
    state.view = {
      scale: s,
      tx: (wrap.clientWidth - w * s) / 2,
      ty: pad,
    };
    applyView();
  }

  function zoomAt(cx, cy, factor) {
    const newScale = Math.max(0.1, Math.min(10, state.view.scale * factor));
    // keep the world-point under (cx,cy) fixed on screen
    const wx = (cx - state.view.tx) / state.view.scale;
    const wy = (cy - state.view.ty) / state.view.scale;
    state.view.tx = cx - wx * newScale;
    state.view.ty = cy - wy * newScale;
    state.view.scale = newScale;
    applyView();
  }

  function isInteractiveTarget(el) {
    if (!el) return false;
    return !!el.closest(
      ".arrow, .arrow-head, .arrow-hit, .arrow-label, " +
      ".collapse-bg, .collapse-dots, .collapse-label, " +
      ".party-box, .party-label, .party-sub"
    );
  }

  function initPanZoom() {
    const wrap = document.querySelector(".diagram-wrap");
    const svg = $("diagram");

    // wheel: ctrl/meta = zoom (also trackpad pinch on macOS), else pan
    wrap.addEventListener("wheel", (e) => {
      if (!state.summary) return;
      e.preventDefault();
      const rect = svg.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      if (e.ctrlKey || e.metaKey) {
        const factor = Math.exp(-e.deltaY * 0.01);
        zoomAt(cx, cy, factor);
      } else {
        state.view.tx -= e.deltaX;
        state.view.ty -= e.deltaY;
        applyView();
      }
    }, { passive: false });

    // drag-to-pan on empty diagram surface
    let dragging = false;
    let startX = 0, startY = 0, baseTx = 0, baseTy = 0;
    svg.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      if (isInteractiveTarget(e.target)) return;
      dragging = true;
      startX = e.clientX; startY = e.clientY;
      baseTx = state.view.tx; baseTy = state.view.ty;
      wrap.classList.add("dragging");
      e.preventDefault();
    });
    window.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      state.view.tx = baseTx + (e.clientX - startX);
      state.view.ty = baseTy + (e.clientY - startY);
      applyView();
    });
    window.addEventListener("mouseup", () => {
      if (!dragging) return;
      dragging = false;
      wrap.classList.remove("dragging");
    });

    // touch pinch (basic): two-finger pinch zoom + one-finger pan
    let touchState = null;
    svg.addEventListener("touchstart", (e) => {
      if (!state.summary) return;
      if (e.touches.length === 1 && !isInteractiveTarget(e.target)) {
        const t = e.touches[0];
        touchState = { mode: "pan", startX: t.clientX, startY: t.clientY, baseTx: state.view.tx, baseTy: state.view.ty };
        e.preventDefault();
      } else if (e.touches.length === 2) {
        const [a, b] = [e.touches[0], e.touches[1]];
        const dist = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
        const rect = svg.getBoundingClientRect();
        touchState = {
          mode: "zoom",
          startDist: dist,
          startScale: state.view.scale,
          cx: (a.clientX + b.clientX) / 2 - rect.left,
          cy: (a.clientY + b.clientY) / 2 - rect.top,
          startTx: state.view.tx,
          startTy: state.view.ty,
        };
        e.preventDefault();
      }
    }, { passive: false });
    svg.addEventListener("touchmove", (e) => {
      if (!touchState) return;
      e.preventDefault();
      if (touchState.mode === "pan" && e.touches.length === 1) {
        const t = e.touches[0];
        state.view.tx = touchState.baseTx + (t.clientX - touchState.startX);
        state.view.ty = touchState.baseTy + (t.clientY - touchState.startY);
        applyView();
      } else if (touchState.mode === "zoom" && e.touches.length === 2) {
        const [a, b] = [e.touches[0], e.touches[1]];
        const dist = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
        const factor = dist / touchState.startDist;
        // restore baseline, then zoom around centroid
        state.view = { scale: touchState.startScale, tx: touchState.startTx, ty: touchState.startTy };
        zoomAt(touchState.cx, touchState.cy, factor);
      }
    }, { passive: false });
    svg.addEventListener("touchend", () => { touchState = null; });
    svg.addEventListener("touchcancel", () => { touchState = null; });

    // controls
    $("zoomIn").addEventListener("click", () => {
      const rect = svg.getBoundingClientRect();
      zoomAt(rect.width / 2, rect.height / 2, 1.25);
    });
    $("zoomOut").addEventListener("click", () => {
      const rect = svg.getBoundingClientRect();
      zoomAt(rect.width / 2, rect.height / 2, 0.8);
    });
    $("zoomReset").addEventListener("click", resetView);
    $("zoomFit").addEventListener("click", fitView);

    // double-click empty area = reset
    svg.addEventListener("dblclick", (e) => {
      if (isInteractiveTarget(e.target)) return;
      resetView();
    });
  }

  function highlightSelected() {
    document.querySelectorAll(".arrow.selected").forEach(el => el.classList.remove("selected"));
    if (!state.selectedKey) return;
    document.querySelectorAll(`.arrow[data-key="${CSS.escape(state.selectedKey)}"]`)
      .forEach(el => el.classList.add("selected"));
  }

  // ---------- detail pane ----------
  async function selectPacket(frame, key) {
    state.selectedKey = key;
    highlightSelected();
    $("detailTitle").textContent = `Frame #${frame}`;
    $("detailBody").innerHTML = '<p class="muted small">Loading…</p>';
    try {
      const d = await api.detail(state.currentPcap, frame);
      renderDetail(d);
    } catch (e) {
      $("detailBody").innerHTML = `<p class="small">Error: ${escapeHTML(e.message)}</p>`;
    }
  }

  function renderDetail(d) {
    const body = $("detailBody");
    body.innerHTML = "";

    // ---- Label editor (per-packet annotation) ----
    state.labels[d.frame] = d.label || state.labels[d.frame] || "";
    const editor = document.createElement("div");
    editor.className = "label-editor";
    editor.innerHTML = `
      <div class="label-head">
        <span class="label-tag">Label</span>
        <span class="label-current muted small" id="labelCurrent"></span>
      </div>
      <div class="label-row">
        <input id="frameLabelInput" type="text" maxlength="200"
               placeholder="Note for this packet — shown above the arrow" />
        <button id="frameLabelSave" class="btn small block-btn">Save</button>
        <button id="frameLabelClear" class="btn small block-btn ghost">Clear</button>
      </div>
    `;
    body.appendChild(editor);

    const input = editor.querySelector("#frameLabelInput");
    const currentDisp = editor.querySelector("#labelCurrent");
    const refreshLabelDisp = () => {
      const v = state.labels[d.frame] || "";
      input.value = v;
      currentDisp.textContent = v ? "" : "no label yet";
    };
    refreshLabelDisp();

    const save = async () => {
      const v = input.value.trim();
      try {
        await api.setLabel(state.currentPcap, d.frame, v);
        if (v) state.labels[d.frame] = v;
        else delete state.labels[d.frame];
        refreshLabelDisp();
        renderDiagram();
      } catch (e) { alert(e.message); }
    };
    const clear = async () => {
      try {
        await api.setLabel(state.currentPcap, d.frame, "");
        delete state.labels[d.frame];
        refreshLabelDisp();
        renderDiagram();
      } catch (e) { alert(e.message); }
    };
    editor.querySelector("#frameLabelSave").addEventListener("click", save);
    editor.querySelector("#frameLabelClear").addEventListener("click", clear);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); save(); }
    });

    // ---- Hide / Unhide this packet ----
    const isHidden = d.hidden === true || state.hidden.has(d.frame);
    if (isHidden) state.hidden.add(d.frame); else state.hidden.delete(d.frame);
    const hideRow = document.createElement("div");
    hideRow.className = "hide-row";
    hideRow.innerHTML = `
      <button id="frameHideToggle" class="btn small block-btn">
        ${isHidden ? "Unhide this packet" : "Hide this packet"}
      </button>
      <span class="muted small">${isHidden
        ? "Hidden — appears as dots in the diagram"
        : "Click to replace this arrow with a dots cluster"}</span>
    `;
    body.appendChild(hideRow);
    hideRow.querySelector("#frameHideToggle").addEventListener("click", async () => {
      try {
        if (state.hidden.has(d.frame)) {
          await api.unhide(state.currentPcap, d.frame);
          state.hidden.delete(d.frame);
        } else {
          await api.hide(state.currentPcap, d.frame);
          state.hidden.add(d.frame);
        }
        // hiding/unhiding changes sequence grouping → re-fetch from server
        renderRequested();
      } catch (e) { alert(e.message); }
    });

    // ---- Summary header (frame, time, length, encap) ----
    const head = document.createElement("div");
    head.className = "layer-node open";
    head.innerHTML = `
      <div class="layer-summary">Frame #${d.frame}: ${d.length} bytes — ${escapeHTML(d.encap)}</div>
      <div class="layer-fields">
        <div class="row"><div class="k">Arrival time</div><div>${escapeHTML(d.time || "")}</div></div>
        <div class="row"><div class="k">Epoch time</div><div>${d.epoch}</div></div>
        <div class="row"><div class="k">Frame length</div><div>${d.length} bytes</div></div>
        <div class="row"><div class="k">Encapsulation</div><div>${escapeHTML(d.encap)}</div></div>
      </div>
    `;
    head.querySelector(".layer-summary").addEventListener("click", () => head.classList.toggle("open"));
    body.appendChild(head);

    // Layers (open by default; user can collapse)
    for (const layer of d.layers) {
      const node = document.createElement("div");
      node.className = "layer-node open";
      const rows = Object.entries(layer.fields || {}).map(([k, v]) => {
        const val = Array.isArray(v) ? v.join(", ") : v;
        return `<div class="row"><div class="k">${escapeHTML(k)}</div><div>${escapeHTML(val)}</div></div>`;
      }).join("");
      let hexHtml = "";
      if (layer.hex_dump) {
        const rows2 = layer.hex_dump.map(r =>
          `<tr><td class="off">${r.offset.toString(16).padStart(4, "0")}</td>` +
          `<td>${escapeHTML(r.hex)}</td>` +
          `<td>${escapeHTML(r.ascii)}</td></tr>`
        ).join("");
        hexHtml = `<table class="hex-table"><tbody>${rows2}</tbody></table>`;
      }
      node.innerHTML = `
        <div class="layer-summary">${escapeHTML(layer.summary || layer.name)}</div>
        <div class="layer-fields">${rows}${hexHtml}</div>
      `;
      node.querySelector(".layer-summary").addEventListener("click", () => node.classList.toggle("open"));
      body.appendChild(node);
    }

    // Frame hex dump always shown
    const hexNode = document.createElement("div");
    hexNode.className = "layer-node open";
    const rows2 = d.hex_dump.map(r =>
      `<tr><td class="off">${r.offset.toString(16).padStart(4, "0")}</td>` +
      `<td>${escapeHTML(r.hex)}</td>` +
      `<td>${escapeHTML(r.ascii)}</td></tr>`
    ).join("");
    hexNode.innerHTML = `
      <div class="layer-summary">Bytes (${d.length})</div>
      <div class="layer-fields"><table class="hex-table"><tbody>${rows2}</tbody></table></div>
    `;
    hexNode.querySelector(".layer-summary").addEventListener("click", () => hexNode.classList.toggle("open"));
    body.appendChild(hexNode);
  }

  function closeDetail() {
    state.selectedKey = null;
    highlightSelected();
    $("detailTitle").textContent = "Packet details";
    $("detailBody").innerHTML = '<p class="muted small">Click an arrow in the diagram to inspect the packet.</p>';
  }

  // ---------- export to PNG ----------
  const EXPORT_CSS = `
    .lifeline{stroke:#000;stroke-width:1}
    .party-label{font-family:monospace;font-size:12px;font-weight:600;fill:#000}
    .party-sub{font-family:monospace;font-size:10px;fill:#5a5a5a}
    .party-box{fill:#fff;stroke:#000;stroke-width:1.5}
    .arrow{stroke:#000;stroke-width:1.2;fill:none}
    .arrow-head{fill:#000}
    .arrow-label{font-family:monospace;font-size:10px;fill:#000}
    .arrow-custom-label{font-family:monospace;font-size:11px;font-weight:700;fill:#000}
    .arrow-hit{stroke:rgba(0,0,0,0);stroke-width:14;fill:none}
    .collapse-bg{fill:#fff;stroke:#000}
    .collapse-dots circle{fill:#000}
    .collapse-label{font-family:monospace;font-size:10px;fill:#000}
    .hidden-line{stroke:#5a5a5a;stroke-width:0.5;stroke-dasharray:2 3}
    .hidden-bg{fill:#fff;stroke:#5a5a5a;stroke-width:1;stroke-dasharray:2 2}
    .hidden-dots circle{fill:#5a5a5a}
    .hidden-label{font-family:monospace;font-size:10px;font-style:italic;fill:#5a5a5a}
  `;
  function exportPng() {
    const svg = $("diagram");
    if (!svg.firstChild) return;
    // Capture the natural content size, ignoring the current pan/zoom.
    const { w: cw, h: ch } = state.contentBounds;
    if (!cw || !ch) return;
    const pad = 20;
    const w = Math.ceil(cw + pad * 2);
    const h = Math.ceil(ch + pad * 2);

    const clone = svg.cloneNode(true);
    const cv = clone.querySelector("#diagramViewport");
    if (cv) cv.setAttribute("transform", `translate(${pad} ${pad})`);
    clone.setAttribute("viewBox", `0 0 ${w} ${h}`);
    clone.setAttribute("width", String(w));
    clone.setAttribute("height", String(h));
    if (!clone.getAttribute("xmlns")) clone.setAttribute("xmlns", SVG_NS);

    const styleNode = document.createElementNS(SVG_NS, "style");
    styleNode.textContent = EXPORT_CSS;
    clone.insertBefore(styleNode, clone.firstChild);
    const xml = new XMLSerializer().serializeToString(clone);
    const blob = new Blob(
      ['<?xml version="1.0" encoding="UTF-8"?>\n', xml],
      { type: "image/svg+xml;charset=utf-8" }
    );
    const url = URL.createObjectURL(blob);
    const img = new Image();
    img.onload = () => {
      const c = document.createElement("canvas");
      c.width = w * 2; c.height = h * 2;
      const ctx = c.getContext("2d");
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, c.width, c.height);
      ctx.scale(2, 2);
      ctx.drawImage(img, 0, 0);
      URL.revokeObjectURL(url);
      c.toBlob((b) => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(b);
        a.download = `p-seq-${Date.now()}.png`;
        a.click();
      }, "image/png");
    };
    img.onerror = () => alert("Failed to render SVG to PNG.");
    img.src = url;
  }

  // ---------- upload area UI state machine ----------
  // The "Upload pcap" button gets replaced by a progress card while a file is
  // being uploaded and then parsed on the server. Three visual states:
  //   idle      → button + hint
  //   uploading → real % from XHR upload progress events
  //   parsing   → indeterminate bar + elapsed-time counter (server is busy
  //               turning the bytes into Scapy packets; we don't have a real %
  //               until the response comes back)
  const uploadUI = {
    parseTimer: null,
    parseStart: 0,
    fileSizeText: "",

    idle() {
      this._clearTimer();
      $("uploadArea").innerHTML = `
        <label class="btn block" for="fileInput">Upload pcap</label>
        <div class="muted small upload-hint">pcap / pcapng / cap</div>
      `;
    },
    uploading(pct) {
      const p = Math.max(0, Math.min(1, pct));
      const pctStr = `${Math.floor(p * 100)}%`;
      const sent = fmtBytes(Math.floor(p * (this.fileSize || 0)));
      $("uploadArea").innerHTML = `
        <div class="upload-progress">
          <div class="upload-progress-head">
            <span class="upload-progress-stage">Uploading</span>
            <span class="upload-progress-pct">${pctStr}</span>
          </div>
          <div class="upload-bar"><div class="upload-bar-fill" style="width:${pctStr}"></div></div>
          <div class="upload-progress-meta">
            <span>${escapeHTML(this.fileName || "")}</span>
            <span>${escapeHTML(sent)} / ${escapeHTML(this.fileSizeText)}</span>
          </div>
        </div>
      `;
    },
    parsing() {
      this._clearTimer();
      this.parseStart = Date.now();
      const tick = () => {
        const elapsed = (Date.now() - this.parseStart) / 1000;
        $("uploadArea").innerHTML = `
          <div class="upload-progress">
            <div class="upload-progress-head">
              <span class="upload-progress-stage">Parsing</span>
              <span class="upload-progress-pct">${elapsed.toFixed(1)}s</span>
            </div>
            <div class="upload-bar"><div class="upload-bar-fill indeterminate"></div></div>
            <div class="upload-progress-meta">
              <span>${escapeHTML(this.fileName || "")}</span>
              <span>${escapeHTML(this.fileSizeText)} · scapy rdpcap</span>
            </div>
          </div>
        `;
      };
      tick();
      this.parseTimer = setInterval(tick, 200);
    },
    _clearTimer() {
      if (this.parseTimer) { clearInterval(this.parseTimer); this.parseTimer = null; }
    },
    armForFile(f) {
      this.fileName = f.name;
      this.fileSize = f.size;
      this.fileSizeText = fmtBytes(f.size);
    },
  };

  // ---------- wire up ----------
  function wire() {
    $("fileInput").addEventListener("change", async (e) => {
      const f = e.target.files[0];
      if (!f) return;
      uploadUI.armForFile(f);
      uploadUI.uploading(0);
      try {
        const entry = await api.upload(
          f,
          (pct) => { if (pct < 1) uploadUI.uploading(pct); },
          () => uploadUI.parsing(),
        );
        uploadUI.idle();
        e.target.value = "";
        await refreshHistory();
        await selectPcap(entry.id);
      } catch (err) {
        uploadUI.idle();
        alert(err.message);
      }
    });

    $("renderBtn").addEventListener("click", renderRequested);
    $("applyFilter").addEventListener("click", renderRequested);
    $("filter").addEventListener("keydown", (e) => { if (e.key === "Enter") renderRequested(); });

    $("closeDetail").addEventListener("click", closeDetail);

    const modal = $("settingsModal");
    const openModal = () => modal.classList.remove("hidden");
    const closeModal = () => modal.classList.add("hidden");
    $("settingsBtn").addEventListener("click", openModal);
    $("closeSettings").addEventListener("click", closeModal);
    modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !modal.classList.contains("hidden")) closeModal();
    });
    $("collapseThreshold").addEventListener("change", (e) => {
      state.settings.collapseThreshold = Math.max(2, parseInt(e.target.value, 10) || 5);
      if (state.selected.length === 2 && state.currentPcap) renderRequested();
    });
    $("showSeconds").addEventListener("change", (e) => {
      state.settings.showSeconds = !!e.target.checked;
      if (state.sequence.length) renderDiagram();
    });
    $("exportBtn").addEventListener("click", exportPng);
  }

  // ---------- boot ----------
  wire();
  initPanZoom();
  window.addEventListener("resize", () => {
    if (state.sequence.length || state.selected.length === 2) renderDiagram();
    syncHeaderHeights();
  });
  refreshHistory();
})();
