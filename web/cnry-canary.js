// SPDX-License-Identifier: LGPL-3.0-only WITH LGPL-3.0-linking-exception
// cnry web component: <cnry-canary src="/.well-known/canary.json" key="ed25519pub:...">
//
// Fetches a cnry/1 statement, verifies it in the browser against the PINNED
// key given in the `key` attribute, and draws the canary on its swing. Any
// failure (fetch error, malformed, bad signature, wrong key, expired, stale
// freshness proof) shows the empty swing: the answer is present or absent,
// nothing in between. Nothing here renews, extends or signs anything.

const SCHEMA = "cnry/1";
const SKEW_MS = 5 * 60 * 1000;
const MAX_PROOF_AGE_MS = 24 * 3600 * 1000;
const TOP = ["schema", "system", "issued", "expires", "statement", "freshness", "key", "signature"];
const FRESH = ["kind", "height", "hash", "time"];
const TS = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;

// ---- verification (exported for tests and other pages) ----

// RFC 8785 for the cnry subset: integers only, members sorted by UTF-16 code units.
export function canonicalize(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error("non-integer number");
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  throw new Error("unsupported value");
}

function b64url(text) {
  const s = text.replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*$/.test(s)) throw new Error("base64");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function sameKeys(obj, names) {
  const k = Object.keys(obj);
  return k.length === names.length && names.every((n) => k.includes(n));
}

function time(text) {
  if (typeof text !== "string" || !TS.test(text)) return NaN;
  return Date.parse(text);
}

async function fingerprint(pub) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", pub));
  return "ed25519:" + Array.from(d.slice(0, 20), (b) => b.toString(16).padStart(2, "0")).join("");
}

let nobleModule;
async function ed25519Verify(sig, msg, pub) {
  try {
    const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
  } catch (_) {
    // No WebCrypto Ed25519 here: use the small vendored pure-JS verifier.
    nobleModule ??= import("./vendor/noble-ed25519.js");
    const noble = await nobleModule;
    return await noble.verifyAsync(sig, msg, pub, { zip215: false });
  }
}

// Returns the statement object when the canary is present, else null.
// `pinned` is "ed25519pub:<base64url>", `now` a Date.
export async function verify(text, pinned, now = new Date()) {
  try {
    if (!pinned.startsWith("ed25519pub:")) return null;
    const pub = b64url(pinned.slice("ed25519pub:".length));
    if (pub.length !== 32) return null;
    const st = JSON.parse(text);
    if (st === null || typeof st !== "object" || Array.isArray(st) || !sameKeys(st, TOP)) return null;
    if (st.schema !== SCHEMA || st.key !== (await fingerprint(pub))) return null;
    if (typeof st.system !== "string" || typeof st.statement !== "string" || typeof st.signature !== "string") return null;
    const f = st.freshness;
    if (f === null || typeof f !== "object" || !sameKeys(f, FRESH)) return null;
    const { signature, ...unsigned } = st;
    const sig = b64url(signature);
    if (sig.length !== 64) return null;
    const msg = new TextEncoder().encode(canonicalize(unsigned));
    if (!(await ed25519Verify(sig, msg, pub))) return null;

    const issued = time(st.issued), expires = time(st.expires), block = time(f.time), t = now.getTime();
    if (Number.isNaN(issued) || Number.isNaN(expires) || Number.isNaN(block)) return null;
    if (issued > t + SKEW_MS || expires <= issued || expires <= t) return null;
    const hashOk = typeof f.hash === "string" && /^[0-9a-f]{64}$/.test(f.hash);
    if (f.kind !== "bitcoin-block" || !Number.isSafeInteger(f.height) || f.height < 1 || !hashOk) return null;
    if (block > issued + SKEW_MS || block > t + SKEW_MS || issued - block > MAX_PROOF_AGE_MS) return null;
    return st;
  } catch (_) {
    return null;
  }
}

// ---- the scene (the same pixels as src/scene.rs; a test compares the sprite) ----

const SPRITE = [
  "........................",
  "..............kkkk......",
  ".............kGGggk.....",
  "............kGgggggk....",
  "............kgggweggk...",
  "............kgggeegkooo.",
  "...........kgggggggkoo..",
  "..........kgggggggyk....",
  ".........kdddgggyyyyk...",
  "........kddddddgyyyyyk..",
  ".......kdddddddgyyyyyk..",
  "....kkkdddddddggyyyyyk..",
  "..kkgggkddddddggyyyyk...",
  ".kggk...kddddggggyyk....",
  ".kk......kkggggggkk.....",
  "...........kkkkkk.......",
  "............f..f........",
  "...........fff.fff......",
];
const PAL = { k: "#22301c", g: "#7fb046", G: "#a6cf5e", d: "#4e7a2f", y: "#d3df5c", o: "#f0a030", e: "#0b0f0c", w: "#ffffff", f: "#d08a40" };
const W = 64, BRANCH_H = 5, SW = 32, SH = 36, H = BRANCH_H + SH;

function drawBranch(c) {
  for (let x = 0; x < W; x++) {
    const y = 2 + (x % 13 >= 6 && x % 13 < 9 ? 1 : 0);
    c.fillStyle = "#9a6a45"; c.fillRect(x, y, 1, 1);
    c.fillStyle = "#6e4a30"; c.fillRect(x, y + 1, 1, 1);
  }
  c.fillStyle = "#6aa84f";
  for (const [x, y] of [[8, 0], [9, 1], [30, 0], [31, 0], [50, 1], [51, 0], [52, 1]]) c.fillRect(x, y, 1, 2);
}

function drawSwing(c, present, right, eyeOpen) {
  c.fillStyle = "#cdb98e"; c.fillRect(3, 0, 1, 33); c.fillRect(28, 0, 1, 33);
  c.fillStyle = "#e0b47a"; c.fillRect(2, 33, 28, 1);
  c.fillStyle = "#a77c4a"; c.fillRect(2, 34, 28, 1);
  if (!present) return;
  for (let r = 0; r < SPRITE.length; r++) {
    for (let cx = 0; cx < 24; cx++) {
      let ch = SPRITE[r][cx];
      if (!eyeOpen && r === 4 && (cx === 16 || cx === 17)) ch = "g";
      if (!eyeOpen && r === 5 && (cx === 16 || cx === 17)) ch = "k";
      if (ch === ".") continue;
      c.fillStyle = PAL[ch];
      c.fillRect(right ? 4 + cx : 4 + (23 - cx), 15 + r, 1, 1);
    }
  }
}

function angle(present, t) {
  if (present) return -5 * Math.cos((2 * Math.PI * t) / 4.4);
  return t >= 8 ? 0 : -5 * Math.exp(-t / 2.2) * Math.cos((2 * Math.PI * t) / 3);
}

// ---- the element ----

const STYLE = `
:host { display: block; text-align: center; }
.scene { position: relative; display: inline-block; line-height: 0; }
canvas { image-rendering: pixelated; image-rendering: crisp-edges; width: calc(64 * var(--px, 6px)); height: calc(41 * var(--px, 6px)); max-width: 100%; }
.note { position: absolute; color: #e8d98a; opacity: 0; font: 1.2rem serif; line-height: 1; animation: rise 3.2s ease-out forwards; pointer-events: none; }
@keyframes rise { 0% { opacity: 0; transform: translateY(0); } 15% { opacity: .95; } 100% { opacity: 0; transform: translateY(-3.2em); } }
.line { margin: .6em 0 .2em; }
.meta { font-size: .85em; opacity: .75; }
button { font: inherit; font-size: .85em; color: inherit; background: transparent; border: 1px solid currentColor; border-radius: 999px; padding: .4em 1em; cursor: pointer; opacity: .85; }
button:focus-visible { outline: 2px solid currentColor; outline-offset: 2px; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
@media (prefers-reduced-motion: reduce) { .note { animation-duration: .01s; } }
`;

const Base = typeof HTMLElement === "undefined" ? class {} : HTMLElement;

class CnryCanary extends Base {
  static observedAttributes = ["src", "key"];

  constructor() {
    super();
    this.present = false;
    this.statement = null;
    this.t0 = performance.now();
    this.soundOn = false;
    this.ctx = null;
    const root = this.attachShadow({ mode: "open" });
    root.innerHTML = `<style>${STYLE}</style><div class="scene" aria-hidden="true"><canvas width="${W}" height="${H}"></canvas></div>
      <div class="line" part="line"></div><div class="meta" part="meta"></div>
      <p class="sr" role="status"></p><button type="button" part="button" hidden aria-pressed="false">Birdsong: off</button>`;
    this.canvas = root.querySelector("canvas");
    this.c = this.canvas.getContext("2d");
    this.lineEl = root.querySelector(".line");
    this.metaEl = root.querySelector(".meta");
    this.statusEl = root.querySelector(".sr");
    this.button = root.querySelector("button");
    this.scene = root.querySelector(".scene");
    this.sprite = document.createElement("canvas");
    this.sprite.width = SW; this.sprite.height = SH;
    this.button.addEventListener("click", () => this.toggleSound());
    this.reduced = matchMedia("(prefers-reduced-motion: reduce)");
  }

  connectedCallback() {
    this.setPx();
    this.onResize = () => this.setPx();
    addEventListener("resize", this.onResize);
    this.raf = requestAnimationFrame((n) => this.frame(n));
    this.refresh();
    this.timer = setInterval(() => this.refresh(), 5 * 60 * 1000);
  }

  disconnectedCallback() {
    cancelAnimationFrame(this.raf);
    clearInterval(this.timer);
    clearTimeout(this.expiry);
    clearTimeout(this.songTimer);
    removeEventListener("resize", this.onResize);
  }

  attributeChangedCallback() {
    if (this.isConnected) this.refresh();
  }

  setPx() {
    const px = Math.max(3, Math.min(10, Math.floor(Math.min(this.clientWidth || innerWidth, 640) / W)));
    this.style.setProperty("--px", px + "px");
  }

  async refresh() {
    const src = this.getAttribute("src") || "/.well-known/canary.json";
    const key = this.getAttribute("key") || "";
    let st = null;
    try {
      const ctl = new AbortController();
      const timeout = setTimeout(() => ctl.abort(), 10000);
      const res = await fetch(src, { cache: "no-store", signal: ctl.signal, credentials: "omit" });
      clearTimeout(timeout);
      if (res.ok) st = await verify(await res.text(), key);
    } catch (_) {
      st = null;
    }
    this.apply(st);
  }

  apply(st) {
    const was = this.present;
    this.present = st !== null;
    this.statement = st;
    clearTimeout(this.expiry);
    if (st) {
      // The moment the statement expires the page shows the empty swing, no reload needed.
      const ms = Date.parse(st.expires) - Date.now();
      this.expiry = setTimeout(() => this.apply(null), Math.min(Math.max(ms, 0), 2 ** 31 - 1));
      this.lineEl.textContent = st.statement;
      this.metaEl.textContent = `${st.system}: signed ${st.issued.slice(0, 10)}, next due by ${st.expires.slice(0, 10)}. Verified in your browser against a pinned key (${st.key}).`;
      this.statusEl.textContent = "The canary is present: the statement is current and verified.";
    } else {
      this.lineEl.textContent = "No current statement.";
      this.metaEl.textContent = "";
      this.statusEl.textContent = "No current statement.";
      this.stopSound();
    }
    this.button.hidden = !this.present || typeof AudioContext === "undefined" && typeof webkitAudioContext === "undefined";
    if (was !== this.present) this.t0 = performance.now();
    this.dispatchEvent(new CustomEvent("cnry-state", { detail: { present: this.present, statement: st } }));
  }

  frame(now) {
    const t = this.reduced.matches ? 0 : (now - this.t0) / 1000;
    const eyeOpen = this.reduced.matches || t % 3.8 >= 0.18;
    const right = Math.floor(t / 14) % 2 === 0;
    const s = this.sprite.getContext("2d");
    s.clearRect(0, 0, SW, SH);
    drawSwing(s, this.present, right, eyeOpen);
    const c = this.c;
    c.clearRect(0, 0, W, H);
    drawBranch(c);
    // Rotate the swing about its top centre, nearest neighbour, like the terminal renderer.
    const [sin, cos] = [Math.sin, Math.cos].map((f) => f((angle(this.present, t) * Math.PI) / 180));
    const src = s.getImageData(0, 0, SW, SH).data;
    const out = c.getImageData(0, 0, W, H);
    const off = (W - SW) / 2;
    for (let y = 0; y < SH; y++) {
      for (let x = 0; x < SW; x++) {
        const dx = x + 0.5 - SW / 2, dy = y + 0.5;
        const sx = Math.floor(dx * cos + dy * sin + SW / 2), sy = Math.floor(-dx * sin + dy * cos);
        if (sx < 0 || sy < 0 || sx >= SW || sy >= SH) continue;
        const i = (sy * SW + sx) * 4;
        if (src[i + 3] === 0) continue;
        const o = ((BRANCH_H + y) * W + off + x) * 4;
        out.data[o] = src[i]; out.data[o + 1] = src[i + 1]; out.data[o + 2] = src[i + 2]; out.data[o + 3] = 255;
      }
    }
    c.putImageData(out, 0, 0);
    // A still picture when reduced motion is asked for: no loop needed.
    if (!this.reduced.matches) this.raf = requestAnimationFrame((n) => this.frame(n));
    else this.raf = setTimeout(() => this.frame(performance.now()), 1000);
  }

  // Birdsong: short synthesised trills, only after the viewer clicks the button.
  toggleSound() {
    this.soundOn = !this.soundOn;
    this.button.setAttribute("aria-pressed", String(this.soundOn));
    this.button.textContent = this.soundOn ? "Birdsong: on" : "Birdsong: off";
    if (!this.soundOn) return this.stopSound(true);
    try {
      const AC = window.AudioContext || window.webkitAudioContext;
      this.ctx ??= new AC();
      this.ctx.resume?.();
    } catch (_) {
      this.ctx = null;
    }
    this.sing();
  }

  stopSound(keepFlag) {
    clearTimeout(this.songTimer);
    if (!keepFlag && this.soundOn) {
      this.soundOn = false;
      this.button.setAttribute("aria-pressed", "false");
      this.button.textContent = "Birdsong: off";
    }
  }

  chirp(t, f0, f1, dur) {
    const o = this.ctx.createOscillator(), g = this.ctx.createGain();
    o.type = "sine";
    o.frequency.setValueAtTime(f0, t);
    o.frequency.exponentialRampToValueAtTime(f1, t + dur);
    g.gain.setValueAtTime(0.0001, t);
    g.gain.exponentialRampToValueAtTime(0.04, t + dur * 0.2);
    g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    o.connect(g); g.connect(this.ctx.destination);
    o.start(t); o.stop(t + dur + 0.02);
  }

  sing() {
    clearTimeout(this.songTimer);
    if (!this.ctx || !this.soundOn || !this.present) return;
    let t = this.ctx.currentTime + 0.05;
    const start = t, tours = 2 + Math.floor(Math.random() * 3);
    for (let i = 0; i < tours; i++) {
      const f0 = 3400 + Math.random() * 2600, f1 = f0 * (Math.random() < 0.5 ? 1.35 : 0.72);
      const dur = 0.025 + Math.random() * 0.03, gap = 0.012 + Math.random() * 0.02;
      const reps = 6 + Math.floor(Math.random() * 14);
      for (let j = 0; j < reps; j++) { this.chirp(t, f0, f1, dur); t += dur + gap; }
      t += 0.04 + Math.random() * 0.12;
    }
    this.notes();
    this.songTimer = setTimeout(() => this.sing(), (t - start + 0.4 + Math.random() * 2.2) * 1000);
  }

  notes() {
    ["\u266a", "\u266b"].forEach((g, k) => {
      const n = document.createElement("span");
      n.className = "note";
      n.textContent = g;
      n.style.left = 60 + k * 4 + "%";
      n.style.top = "52%";
      n.style.animationDelay = k * 0.5 + "s";
      this.scene.appendChild(n);
      setTimeout(() => n.remove(), 4200);
    });
  }
}

if (typeof customElements !== "undefined" && !customElements.get("cnry-canary")) {
  customElements.define("cnry-canary", CnryCanary);
}
