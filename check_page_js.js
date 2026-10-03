/* 页面脚本回归检查 —— 用最小 DOM shim 真跑 cf_web.py 里的 <script>, 逼出
 * 被 poll() 自己的 catch 吞掉的 ReferenceError。
 *
 * 为什么需要它: v3.0.0 删掉 STATE.mode_name 时, JS 里 `+mname` 漏删 ->
 * poll() 第一行就 ReferenceError -> 被 console.error 吞掉 -> 页面每 2 秒
 * 静默失败一次, pill/日志/统计全部停更。现象是"扫描根本没启动", 但扫描器
 * 其实跑得好好的。这类删字段带出的悬空引用, 静态正则查不准(分不清正则
 * 字面量、模板字符串里的 HTML), 只能真跑一遍。
 *
 * 用法:
 *   node check_page_js.js [cf_web.py]
 *   node check_page_js.js cf_web.py '{"running":true,"stage":"monitor","phase":"monitor"}'
 *
 * 退出码 0 = 各分支的 pill 都渲染出来了且无异常; 1 = 有未捕获异常/pill 为空。
 */
"use strict";
const fs = require("fs"), vm = require("vm"), path = require("path");

const target = process.argv[2] || path.join(__dirname, "cf_web.py");
const OVERRIDE = JSON.parse(process.argv[3] || "{}");
const src = fs.readFileSync(target, "utf8");

const m = /<script>\n([\s\S]*?)\n<\/script>/.exec(src);
if (!m) { console.error("✗ cf_web.py 里没找到 <script> 块"); process.exit(2); }
const js = m[1];

// ---- 最小 DOM ----
function el(id) {
  const grad = { addColorStop() {} };
  const ctx2d = new Proxy({}, {
    get: (t, k) => {
      if (k === "canvas") return { width: 600, height: 120 };
      if (k === "createLinearGradient" || k === "createRadialGradient") return () => grad;
      if (k === "measureText") return () => ({ width: 30 });
      if (k === "getImageData") return () => ({ data: new Uint8ClampedArray(4) });
      return () => {};
    },
    set: () => true,
  });
  return {
    id, textContent: "", innerHTML: "", value: "", checked: false, disabled: false,
    className: "", title: "", src: "", href: "", type: "", placeholder: "", htmlFor: "",
    style: new Proxy({}, { get: (t, k) => (k in t ? t[k] : ""), set: (t, k, v) => { t[k] = v; return true; } }),
    dataset: {}, children: [], childNodes: [], firstChild: null,
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    appendChild(c) { this.children.push(c); return c; },
    insertBefore(c) { this.children.push(c); return c; },
    replaceChildren() {}, normalize() {}, remove() {}, removeChild() {},
    setAttribute() {}, getAttribute() { return null; }, removeAttribute() {}, hasAttribute() { return false; },
    addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
    querySelector() { return null; }, querySelectorAll() { return []; },
    closest() { return null; }, focus() {}, blur() {}, click() {},
    scrollIntoView() {}, insertAdjacentHTML() {},
    cloneNode() { return el("clone"); },
    getBoundingClientRect() { return { width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 }; },
    getContext() { return ctx2d; },
  };
}

const cache = {};
const document = {
  getElementById: (id) => (cache[id] ||= el(id)),
  createElement: () => el("new"),
  querySelector: () => null,
  querySelectorAll: () => [],
  body: el("body"), documentElement: el("html"), head: el("head"),
  addEventListener() {}, removeEventListener() {},
  execCommand() { return true; },
};

// ---- 各端点的假响应(字段与 cf_web.py 的 /api/status、/api/stats 保持一致) ----
const T = Math.floor(Date.now() / 1000);
const STATUS_BASE = {
  running: true, stage: "probe", msg: "扫描中 · 测试", phase: "discover",
  round: 3, total: 500, probed: 120, ok_now: 40, last_ok: 40,
  active: 500, fresh: 500, monitor_due: 7, label: "官方全网 + IPv6:公共",
  started_at: 0, last_cycle: 0, db: "/x/cf_ips.db", version: "3.0.0", budgets: {},
  lifecycle: {
    v4: { active: 500, fresh: 500, reserve: 9600, total: 10100, target: 500, cap: 10000, deficit: 0, deficit_reserve: 0, count: 500, phase: "discover" },
    v6: { active: 500, fresh: 500, reserve: 8900, total: 9400, target: 500, cap: 10000, deficit: 0, deficit_reserve: 300, count: 300, phase: "fill" },
  },
  log: [[T, "本轮完成 · 抽查 500 个，其中可用 220 个"], [T, "库存 · v4 可用 500｜备用 9600｜待补 0"]],
};
const STATUS = Object.assign({}, STATUS_BASE, OVERRIDE);
const STATS = {
  tested_all: 123456, alive: 10000, verified: 9000, withbw: 4000,
  avglat: 88.5, maxbw: 92.4, minlat: 42.1, coverage: 63.2,
  colos: [["HKG", 10]], countries: [["HK", 10]],
  lat: { labels: ["50"], data: [5] }, bw: { labels: ["50"], data: [5] },
};
const SETTINGS = {
  operator: "", ports: "443", count: "500", concurrency: "50", bench: "20",
  backfill: "300", recheck: "200", bench_parallel: "8", bench_size: "64000000",
  bench_timeout: "5", bench_daily: "8000", bench_pause: "1800",
  bw_stale_hours: "24", colo_stale_days: "7", bench_host: "h",
  target_active: "500", explore_interval: "30", explore_fraction: "10",
  count_v6: "1000", ipv6: "1", v4_on: "1", tls_check: "1", v6_official: "1", operator_v6: "",
};
const TABLE = { total: 0, offset: 0, limit: 50, rows: [] };
const SERVICE = { managed: true, unit: "cf-optimizer.service", active: true, enabled: true, can_control: true, systemctl: "/usr/bin/systemctl", message: "", need_sudo: true, can_register: true };

function pick(u) {
  if (u.includes("/api/status")) return STATUS;
  if (u.includes("/api/stats")) return STATS;
  if (u.includes("/api/table")) return TABLE;
  if (u.includes("/api/settings")) return SETTINGS;
  if (u.includes("/api/service")) return SERVICE;
  if (u.includes("/api/ports")) return ["443", "2053", "2083", "8443"];
  return {};
}
const errs = [];
const consoleShim = {
  log() {}, debug() {}, info() {}, warn() {}, dir() {}, table() {},
  error: (...a) => errs.push(["error", a.map(String).join(" ")]),
};
const fetchLog = [];
function fetchShim(url) {
  const u = String(url);
  fetchLog.push(u);
  const p = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(pick(u)), text: () => Promise.resolve("{}") });
  p.catch(() => {});
  return p;
}

// ---- 浏览器全局 ----
const winShim = { addEventListener() {}, removeEventListener() {}, location: { href: "http://x/", protocol: "http:", reload() {} } };
const ctx = {
  document, console: consoleShim, fetch: fetchShim, window: winShim,
  addEventListener() {}, removeEventListener() {},
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  performance: { now: () => 0 },
  requestAnimationFrame: (f) => { try { f(0); } catch (e) {} return 0; }, cancelAnimationFrame() {},
  setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {},
  ResizeObserver: class { observe() {} disconnect() {} unobserve() {} },
  IntersectionObserver: class { observe() {} disconnect() {} unobserve() {} },
  MutationObserver: class { observe() {} disconnect() {} },
  matchMedia: () => ({ matches: false, addEventListener() {}, addListener() {} }),
  navigator: { clipboard: { writeText() {} }, userAgent: "node" },
  location: winShim.location, history: {},
  alert() {}, confirm: () => true, prompt: () => "",
  getComputedStyle: () => ({ getPropertyValue: () => "" }),
  devicePixelRatio: 1, innerWidth: 1400, innerHeight: 900, scrollY: 0,
  URLSearchParams, Blob, FormData, TextEncoder, TextDecoder,
  Uint8Array, Int32Array, Float64Array, ArrayBuffer, Uint8ClampedArray,
  btoa, atob, crypto: {}, AbortController: class { constructor() { this.signal = { addEventListener() {} }; } },
  JSON, Math, Date, Object, Array, String, Number, Boolean, Promise, Set, Map, WeakMap,
  Error, TypeError, RangeError, isNaN, parseInt, parseFloat,
  encodeURIComponent, decodeURIComponent, RegExp, Symbol, Infinity, NaN, undefined,
  structuredClone: (x) => x,
};
ctx.globalThis = ctx;
Object.assign(winShim, ctx, { document, fetch: fetchShim, console: consoleShim });

// ---- 跑 ----
let fatal = null;
vm.createContext(ctx);
process.on("uncaughtException", (e) => { fatal = e; });

(async () => {
  try { vm.runInContext(js, ctx, { filename: "page.js" }); }
  catch (e) {
    // 顶层异常多来自 shim 不完整(比如某个 querySelector 返回 null), 不算页面 bug
    console.log("· 顶层执行中断: " + e.name + ": " + e.message);
  }
  await new Promise((r) => setImmediate(r));

  const before = errs.length;
  try { await ctx.poll(); }
  catch (e) { errs.push(["error", "poll() 抛出 " + e.name + ": " + e.message]); }
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));

  const pill = cache["pill"];
  const pillText = pill ? pill.textContent : null;
  const logRows = cache["logBox"] ? (cache["logBox"].children || []).length : null;
  const newErrs = errs.slice(before);

  console.log("· 抓到的 fetch 端点: " + JSON.stringify([...new Set(fetchLog)]));
  console.log("· poll() 异常 " + newErrs.length + " 条");
  for (const [lv, msg] of newErrs.slice(0, 20)) console.log("    [" + lv + "] " + msg);
  console.log("· pill = " + JSON.stringify(pillText));
  if (logRows !== null) console.log("· 日志区渲染 " + logRows + " 行");

  const bad = newErrs.length > 0 || fatal || !pillText;
  if (bad) {
    console.error("✗ 失败: 页面脚本有未捕获异常或 pill 没渲染 —— 这会让状态栏/日志/统计静默停更");
    if (fatal) console.error("  未捕获: " + fatal.name + ": " + fatal.message);
    process.exit(1);
  }
  console.log("✓ 通过: poll() 无异常, 状态栏已渲染");
})();