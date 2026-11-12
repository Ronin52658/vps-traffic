/* 演示站模拟后端：拦截 fetch("/api/...")，在浏览器内模拟 server.py 的行为 */
(() => {
  const TZ_OFF = 8 * 3600, H = 3600, D = 86400, GiB = 1024 ** 3, DAYS = 120;
  const nowS = () => Math.floor(Date.now() / 1000);

  // ---- 时间工具（Asia/Shanghai，无夏令时）
  const ld = ts => { const d = new Date((ts + TZ_OFF) * 1000); return {y: d.getUTCFullYear(), m: d.getUTCMonth() + 1, d: d.getUTCDate(), h: d.getUTCHours()}; };
  const lm = (y, m, d) => Date.UTC(y, m - 1, d) / 1000 - TZ_OFF;
  const dim = (y, m) => new Date(Date.UTC(y, m, 0)).getUTCDate();
  const p2 = n => String(n).padStart(2, "0");
  const iso = ts => { const x = ld(ts); return `${x.y}-${p2(x.m)}-${p2(x.d)}`; };
  const fromIso = s => { const [y, m, d] = s.split("-").map(Number); return lm(y, m, d); };
  const dayStart = ts => { const x = ld(ts); return lm(x.y, x.m, x.d); };
  function mb(y, m, day) { while (m > 12) { m -= 12; y++; } while (m < 1) { m += 12; y--; } return lm(y, m, Math.min(day, dim(y, m))); }
  function nextB(s, t) {
    if (s.reset_type === "monthly") { const x = ld(t); for (let i = 0; i < 3; i++) { const b = mb(x.y, x.m + i, s.reset_day); if (b > t) return b; } }
    if (s.reset_type === "interval") { const a = fromIso(s.anchor), n = s.interval_days * D, k = Math.floor((t - a) / n); for (const j of [k, k + 1, k + 2]) { const b = a + j * n; if (b > t) return b; } }
    return null;
  }
  function prevB(s, t) {
    if (s.reset_type === "monthly") { const x = ld(t); for (let i = 0; i > -3; i--) { const b = mb(x.y, x.m + i, s.reset_day); if (b <= t) return b; } }
    if (s.reset_type === "interval") { const a = fromIso(s.anchor), n = s.interval_days * D, k = Math.floor((t - a) / n); for (const j of [k + 1, k, k - 1]) { const b = a + j * n; if (b <= t) return b; } }
    return null;
  }
  const billed = (rx, tx, m) => m === "out" ? tx : m === "in" ? rx : m === "max" ? Math.max(rx, tx) : rx + tx;

  // ---- 可重现的随机数
  let seed = 20261111;
  const rnd = () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  const tok = () => Array.from({length: 32}, () => "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"[Math.floor(Math.random() * 56)]).join("");

  // 晚间高峰、午间小高峰的日内曲线
  const W = (() => { const w = []; for (let h = 0; h < 24; h++) w.push(0.35 + Math.exp(-((h - 21) ** 2) / 14) + 0.35 * Math.exp(-((h - 13) ** 2) / 8)); const s = w.reduce((a, b) => a + b); return w.map(v => v / s); })();

  const now0 = nowS(), today = dayStart(now0), first = today - (DAYS - 1) * D;
  const SEEDS = [
    {name: "HK-NAT-01", country: "HK", ip: "203.0.113.24", sysSpec: {os: "Debian GNU/Linux 12 (bookworm)", kernel: "6.1.0-27-cloud-amd64", arch: "x86_64", cpu_model: "AMD EPYC 7B13", cores: 1, virt: "lxc", mem: 512, disk: 5, cpu: 18, memF: .34, diskF: .41, tcp: 140, procs: 38, up: 41}, note: "", quota_gb: 1000, billing: "sum", reset_type: "monthly", reset_day: 1, avg: 21, boost: [11, 2.7], rxShare: 0.71, iface: "eth0", hostname: "hk-nat-01"},
    {name: "JP-Tokyo-IIJ", country: "JP", ip: "198.51.100.77", sysSpec: {os: "Debian GNU/Linux 13 (trixie)", kernel: "6.12.38+deb13-cloud-amd64", arch: "x86_64", cpu_model: "Intel(R) Xeon(R) Gold 6148 CPU @ 2.40GHz", cores: 2, virt: "kvm", mem: 2048, disk: 40, cpu: 6, memF: .22, diskF: .18, tcp: 60, procs: 96, up: 87}, quota_gb: 500, billing: "out", reset_type: "monthly", reset_day: 15, avg: 11, rxShare: 0.32, iface: "ens3", hostname: "tyo-iij", manualSplit: 52},
    {name: "US-LA-CN2GIA", country: "US", ip: "198.51.100.140", sysSpec: {os: "Debian GNU/Linux 12 (bookworm)", kernel: "6.1.0-31-amd64", arch: "x86_64", cpu_model: "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", cores: 2, virt: "kvm", mem: 1024, disk: 20, cpu: 12, memF: .41, diskF: .29, tcp: 210, procs: 84, up: 55}, quota_gb: 2000, billing: "max", reset_type: "monthly", reset_day: 1, avg: 34, rxShare: 0.62, iface: "eth0", hostname: "lax-gia"},
    {name: "SG-Relay", country: "SG", ip: "203.0.113.201", sysSpec: {os: "Debian GNU/Linux 11 (bullseye)", kernel: "5.10.0-33-amd64", arch: "x86_64", cpu_model: "AMD EPYC 7543 32-Core Processor", cores: 1, virt: "openvz", mem: 256, disk: 3, cpu: 4, memF: .48, diskF: .52, tcp: 35, procs: 21, up: 12}, quota_gb: 300, billing: "sum", reset_type: "interval", interval_days: 30, anchorDaysAgo: 77, avg: 6.2, rxShare: 0.5, iface: "venet0", hostname: "sg-relay"},
    {name: "DE-Hetzner-AX", country: "DE", ip: "203.0.113.88", sysSpec: {os: "Debian GNU/Linux 12 (bookworm)", kernel: "6.1.0-28-amd64", arch: "x86_64", cpu_model: "AMD Ryzen 5 3600 6-Core Processor", cores: 12, virt: "none", mem: 65536, disk: 1024, cpu: 23, memF: .37, diskF: .63, tcp: 820, procs: 312, up: 203, swap: 4096}, quota_gb: 20480, billing: "out", reset_type: "monthly", reset_day: 5, avg: 260, rxShare: 0.28, iface: "enp7s0", hostname: "fsn-ax41"},
    {name: "KR-NAT-mini", country: "KR", ip: "198.51.100.9", sysSpec: {os: "Debian GNU/Linux 12 (bookworm)", kernel: "6.1.0-25-cloud-amd64", arch: "x86_64", cpu_model: "Intel Core Processor (Broadwell)", cores: 1, virt: "kvm", mem: 512, disk: 10, cpu: 3, memF: .29, diskF: .36, tcp: 18, procs: 44, up: 9}, quota_gb: 200, billing: "sum", reset_type: "manual", avg: 2.4, rxShare: 0.55, iface: "eth0", hostname: "kr-nat", manualAgo: 37, offlineAgo: 3 * H + 1260},
  ];

  let nextId = 1, nextCycle = 1;
  const S = [];
  for (const sd of SEEDS) {
    const s = {id: nextId++, note: "", reset_day: 1, interval_days: 30, ...sd, token: tok(), hourly: new Map(), cycles: [], created_at: first, last_seen: now0, rate_rx: 0, rate_tx: 0};
    s.anchor = iso(sd.anchorDaysAgo ? today - sd.anchorDaysAgo * D : first);
    if (sd.offlineAgo) s.last_seen = now0 - sd.offlineAgo;
    const stopAt = s.last_seen;
    // 每小时明细
    for (let k = DAYS - 1; k >= 0; k--) {
      const ds = today - k * D;
      const wk = new Date((ds + TZ_OFF) * 1000).getUTCDay();
      let daily = s.avg * (0.72 + 0.56 * rnd()) * (wk === 0 || wk === 6 ? 1.25 : 1);
      if (s.boost && k < s.boost[0]) daily *= s.boost[1];
      for (let h = 0; h < 24; h++) {
        const ts = ds + h * H;
        if (ts >= stopAt) break;
        const frac = ts + H > stopAt ? (stopAt - ts) / H : 1;
        const v = daily * GiB * W[h] * (0.65 + 0.7 * rnd()) * frac;
        const rx = Math.round(v * s.rxShare);
        s.hourly.set(ts, [rx, Math.round(v) - rx]);
      }
    }
    // 周期
    if (s.reset_type === "manual") {
      const t = today - sd.manualAgo * D + 14 * H + 23 * 60;
      s.cycles.push({start: first, end: t, closed: true, reason: "manual"}, {start: t, end: null, closed: false});
    } else {
      let b = nextB(s, first);
      while (b <= now0) { const e = nextB(s, b); s.cycles.push({start: b, end: e, closed: e <= now0, reason: e <= now0 ? "auto" : null}); b = e; }
      if (sd.manualSplit) {
        const t = today - sd.manualSplit * D + 10 * H + 47 * 60;
        const i = s.cycles.findIndex(c => c.start <= t && (c.end === null || t < c.end));
        if (i >= 0) { const c = s.cycles[i]; s.cycles.splice(i, 1, {start: c.start, end: t, closed: true, reason: "manual"}, {...c, start: t}); }
      }
    }
    for (const c of s.cycles) {
      c.id = nextCycle++; c.quota_gb = s.quota_gb; c.billing = s.billing; c.rx = 0; c.tx = 0;
      for (const [ts, [rx, tx]] of s.hourly) if (ts >= c.start && (c.end === null || ts < c.end)) { c.rx += rx; c.tx += tx; }
    }
    S.push(s);
  }

  // ---- 实时模拟：每次请求时补上距离上次的流量
  let lastTick = now0;
  function curCycle(s, now) {
    let c = s.cycles.find(x => !x.closed);
    if (!c) { const st = prevB(s, now) ?? now; c = {id: nextCycle++, start: st, end: nextB(s, st), closed: false, rx: 0, tx: 0, quota_gb: s.quota_gb, billing: s.billing}; s.cycles.push(c); }
    while (c.end !== null && now >= c.end) {
      c.closed = true; c.reason = "auto";
      const n = {id: nextCycle++, start: c.end, end: nextB(s, c.end), closed: false, rx: 0, tx: 0, quota_gb: s.quota_gb, billing: s.billing};
      s.cycles.push(n); c = n;
    }
    return c;
  }
  // ---- 系统指标：按时间生成的平滑曲线（同一时刻结果固定），实时图和历史图都由它而来
  const hash = (t, k) => { const x = Math.sin(t * 12.9898 + k * 78.233) * 43758.5453; return x - Math.floor(x); };
  const smooth = (t, k, period) => { const a = Math.floor(t / period), f = t / period - a, u = f * f * (3 - 2 * f); return hash(a, k) * (1 - u) + hash(a + 1, k) * u; };
  const MB = 1048576;
  function metricAt(s, t) {
    const p = s.sysSpec, k = s.id * 7, h = ld(Math.floor(t)).h;
    const wave = 0.6 + 0.8 * W[h] * 24 / 2.2;
    const cpu = Math.min(100, Math.max(0.2, p.cpu * wave * (0.6 + 0.8 * smooth(t, k, 300)) + 6 * (hash(Math.floor(t / 3), k) - 0.5)));
    const memT = p.mem * MB, diskT = p.disk * 1024 * MB, swapT = (p.swap || 0) * MB;
    const base = s.avg * (s.boost ? s.boost[1] : 1) * GiB * W[h] / H;
    const r = base * (0.6 + 0.8 * smooth(t, k + 1, 120)) * (0.85 + 0.3 * hash(Math.floor(t / 3), k + 2));
    return {
      ts: t, cpu: +cpu.toFixed(1), load1: +(cpu / 100 * p.cores * 1.1 + 0.02).toFixed(2),
      mem_used: Math.round(memT * Math.min(.95, p.memF * (0.92 + 0.16 * smooth(t, k + 3, 1800)))), mem_total: memT,
      swap_used: Math.round(swapT * 0.04 * smooth(t, k + 4, 7200)), swap_total: swapT,
      disk_used: Math.round(diskT * p.diskF * (1 + 0.002 * (t - now0) / 86400)), disk_total: diskT,
      rx_rate: r * s.rxShare, tx_rate: r * (1 - s.rxShare),
      tcp: Math.round(p.tcp * wave * (0.8 + 0.4 * smooth(t, k + 5, 240))), udp: Math.round(p.tcp * 0.08 * (0.5 + smooth(t, k + 6, 400))),
      procs: Math.round(p.procs * (0.95 + 0.1 * smooth(t, k + 7, 900))),
    };
  }
  function sysOf(s, now) {
    if (!s.sysSpec) return null;
    const m = metricAt(s, now), p = s.sysSpec;
    return {cpu: m.cpu, load: [m.load1, +(m.load1 * .92).toFixed(2), +(m.load1 * .85).toFixed(2)],
      mem_total: m.mem_total, mem_used: m.mem_used, swap_total: m.swap_total, swap_used: m.swap_used,
      disk_total: m.disk_total, disk_used: m.disk_used, tcp: m.tcp, udp: m.udp, procs: m.procs,
      uptime: Math.round(p.up * 86400 + (now - now0) + 3600 * 5 + 1234)};
  }
  function metricsSeries(s, rng, now) {
    if (!s.sysSpec) return [];
    const end = s.offlineAgo ? s.last_seen : now;
    const spans = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800};
    const span = spans[rng] || 240, step = rng in spans ? Math.max(60, Math.floor(span / 240 / 60) * 60) : 3;
    const out = [];
    for (let t = end - span; t <= end; t += step) out.push(metricAt(s, rng in spans ? t - t % step : t));
    return out;
  }

  function tick() {
    const now = nowS(), dt = now - lastTick;
    if (dt <= 0) return;
    lastTick = now;
    const h = ld(now).h;
    for (const s of S) {
      if (s.offlineAgo || s.fresh) continue;
      const base = s.avg * (s.boost ? s.boost[1] : 1) * GiB * W[h] / H;
      const mt = metricAt(s, now);
      s.rate_rx = mt.rx_rate; s.rate_tx = mt.tx_rate;
      const rx = Math.round(s.rate_rx * Math.min(dt, 600)), tx = Math.round(s.rate_tx * Math.min(dt, 600));
      const hb = now - now % H, cell = s.hourly.get(hb) || [0, 0];
      s.hourly.set(hb, [cell[0] + rx, cell[1] + tx]);
      const c = curCycle(s, now); c.rx += rx; c.tx += tx;
      s.last_seen = now;
    }
  }
  tick();

  function summary(s, now) {
    const c = curCycle(s, now), t0 = dayStart(now);
    let rx = 0, tx = 0;
    for (const [ts, v] of s.hourly) if (ts >= t0) { rx += v[0]; tx += v[1]; }
    const online = s.last_seen > 0 && now - s.last_seen <= 180;
    return {
      id: s.id, name: s.name, note: s.note, quota_gb: s.quota_gb, billing: s.billing, reset_type: s.reset_type,
      reset_day: s.reset_day, interval_days: s.interval_days, anchor: s.anchor, online, last_seen: s.last_seen,
      rate_rx: online ? s.rate_rx : 0, rate_tx: online ? s.rate_tx : 0, iface: s.iface || "", hostname: s.hostname || "",
      ip: s.ip || "", country: s.countryManual || s.country || "", country_manual: s.countryManual || "", country_auto: s.country || "", sys: sysOf(s, online ? now : s.last_seen),
      info: s.sysSpec ? {os: s.sysSpec.os, kernel: s.sysSpec.kernel, arch: s.sysSpec.arch, cpu_model: s.sysSpec.cpu_model, cores: s.sysSpec.cores, virt: s.sysSpec.virt} : null,
      today: {rx, tx}, cycle: {id: c.id, start: c.start, end: c.end, rx: c.rx, tx: c.tx, used: billed(c.rx, c.tx, s.billing)},
    };
  }

  function clean(b, partial) {
    const o = {};
    if ("name" in b || !partial) { const n = String(b.name || "").trim().slice(0, 64); if (!n) throw new Error("名称不能为空"); o.name = n; }
    if ("quota_gb" in b || !partial) o.quota_gb = Math.max(0, +b.quota_gb || 0);
    if ("billing" in b || !partial) { if (!["sum", "out", "in", "max"].includes(b.billing || "sum")) throw new Error("计费方式无效"); o.billing = b.billing || "sum"; }
    if ("reset_type" in b || !partial) { if (!["monthly", "interval", "manual"].includes(b.reset_type || "monthly")) throw new Error("重置方式无效"); o.reset_type = b.reset_type || "monthly"; }
    if ("reset_day" in b || !partial) { const d = +b.reset_day || 1; if (d < 1 || d > 31) throw new Error("重置日须在 1–31"); o.reset_day = d; }
    if ("interval_days" in b || !partial) { const n = +b.interval_days || 30; if (n < 1 || n > 3650) throw new Error("间隔天数须在 1–3650"); o.interval_days = n; }
    if (b.anchor) o.anchor = b.anchor;
    if ("country" in b) { const c = String(b.country || "").trim().toUpperCase(); if (c && !/^[A-Z]{2}$/.test(c)) throw new Error("地区请填两位国家代码，例如 SG、HK、US"); o.countryManual = c; }
    return o;
  }

  // 演示站同样需要输入密码；登录状态记在本浏览器，关闭后再打开不用重新登录
const LS_KEY = "vt-demo-login";
let loggedIn = false;
  // 演示站主题默认跟随查看者当前的设置
  let theme0 = "system"; try { theme0 = localStorage.getItem("vt-theme") || "system"; } catch (e) {}
  const IV = {interval: 3, idle_interval: 60, site_name: "VPS 流量", theme: theme0};
try { loggedIn = Number(localStorage.getItem(LS_KEY) || 0) > Date.now(); } catch (e) {}
const keepLogin = on => { try { on ? localStorage.setItem(LS_KEY, String(Date.now() + 30 * 86400000)) : localStorage.removeItem(LS_KEY); } catch (e) {} };
  const R = (status, obj) => new Response(JSON.stringify(obj), {status, headers: {"Content-Type": "application/json"}});

  async function handle(path, method, body, qs) {
    const now = nowS();
    if (path === "/api/site") return R(200, {name: IV.site_name, theme: IV.theme});
    if (path === "/api/login" && method === "POST") {
      if (String(body.password || "") === "demo") { loggedIn = true; keepLogin(true); return R(200, {ok: true}); }
      await new Promise(r => setTimeout(r, 500)); return R(401, {error: "密码错误"});
    }
    if (path === "/api/logout") { loggedIn = false; keepLogin(false); return R(200, {ok: true}); }
    if (!loggedIn) return R(401, {error: "未登录"});
    tick();
    if (path === "/api/range") {
      const [start, days] = parseRange(qs, now), end = start + days * D;
      const servers = S.map(s => { let rx = 0, tx = 0; for (const [ts, v] of s.hourly) if (ts >= start && ts < end) { rx += v[0]; tx += v[1]; }
        return {id: s.id, name: s.name, billing: s.billing, rx, tx, used: billed(rx, tx, s.billing)}; });
      return R(200, {start: iso(start), end: iso(end - D), servers, rx: servers.reduce((a, x) => a + x.rx, 0), tx: servers.reduce((a, x) => a + x.tx, 0)});
    }
    if (path === "/api/password") return R(400, {error: "演示站不能修改密码"});
    if (path === "/api/meta") return R(200, {tz: "Asia/Shanghai", now, base_url: "https://traffic.example.com", telegram: true, session_days: 30, interval: IV.interval, idle_interval: IV.idle_interval, site_name: IV.site_name});
    if (path === "/api/order" && method === "POST") {
      const ids = body.ids || [];
      S.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
      return R(200, {ok: true});
    }
    if (path === "/api/settings" && method === "POST") {
      if ("theme" in body) {
        if (!["system", "light", "dark"].includes(body.theme)) throw new Error("主题无效");
        IV.theme = body.theme;
      }
      if ("site_name" in body) {
        const n = String(body.site_name).replace(/[<>]/g, "").trim();
        if (n.length < 1 || n.length > 40) throw new Error("面板名称须为 1–40 个字符");
        IV.site_name = n;
      }
      for (const k of ["interval", "idle_interval"]) if (k in body) {
        const n = +body[k]; if (!Number.isInteger(n) || n < 1 || n > 300) throw new Error("间隔须在 1–300 秒"); IV[k] = n;
      }
      return R(200, {ok: true, ...IV});
    }
    if (path === "/api/restore" && method === "POST") {
      const head = new Uint8Array(await body.slice(0, 16).arrayBuffer());
      if (String.fromCharCode(...head) !== "SQLite format 3\u0000") return R(400, {error: "这不是 SQLite 数据库文件"});
      const st = iso(now).replaceAll("-", "") + "-" + p2(ld(now).h) + "0000";
      return R(200, {servers: S.length, cycles: S.reduce((a, s) => a + s.cycles.length, 0), hourly: S.reduce((a, s) => a + s.hourly.size, 0), safety_copy: `traffic.db.before-restore-${st}`});
    }
    if (path === "/api/servers") {
      if (method === "GET") return R(200, S.map(s => summary(s, now)));
      const f = clean(body);
      const s = {id: nextId++, note: "", ...f, anchor: f.anchor || iso(now), token: tok(), hourly: new Map(), cycles: [], created_at: now, last_seen: 0, rate_rx: 0, rate_tx: 0, avg: 0, rxShare: 0.5, fresh: true};
      curCycle(s, now); S.push(s);
      return R(200, {id: s.id, token: s.token});
    }
    const m = path.match(/^\/api\/servers\/(\d+)(?:\/(daily|hourly|cycles|reset|token|metrics))?$/);
    if (!m) return R(404, {error: "not found"});
    const s = S.find(x => x.id === +m[1]), sub = m[2];
    if (!s) return R(404, {error: "服务器不存在"});
    if (!sub && method === "GET") return R(200, {...summary(s, now), token: s.token});
    if (!sub && method === "PUT") {
      Object.assign(s, clean(body, true));
      const c = curCycle(s, now); c.end = nextB(s, now); c.quota_gb = s.quota_gb; c.billing = s.billing; curCycle(s, now);
      return R(200, {ok: true});
    }
    if (!sub && method === "DELETE") { S.splice(S.indexOf(s), 1); return R(200, {ok: true}); }
    if (sub === "daily") {
      const [start, days] = parseRange(qs, now), out = [];
      for (let i = 0; i < days; i++) {
        const a = start + i * D; let rx = 0, tx = 0;
        for (let h = 0; h < 24; h++) { const v = s.hourly.get(a + h * H); if (v) { rx += v[0]; tx += v[1]; } }
        out.push({date: iso(a), rx, tx});
      }
      return R(200, out);
    }
    if (sub === "metrics") return R(200, metricsSeries(s, qs.get("range") || "live", now));
    if (sub === "hourly") {
      const a = fromIso(qs.get("date") || iso(now));
      return R(200, Array.from({length: 24}, (_, h) => { const v = s.hourly.get(a + h * H) || [0, 0]; return {hour: h, rx: v[0], tx: v[1]}; }));
    }
    if (sub === "cycles") {
      curCycle(s, now);
      return R(200, [...s.cycles].sort((a, b) => b.start - a.start || b.id - a.id).map(c => ({
        id: c.id, start: c.start, end: c.end, rx: c.rx, tx: c.tx, used: billed(c.rx, c.tx, c.billing), quota_gb: c.quota_gb,
        billing: c.billing, closed: c.closed, closed_at: c.closed ? c.end : null, reason: c.reason || null})));
    }
    if (sub === "reset" && method === "POST") {
      const c = curCycle(s, now); c.closed = true; c.reason = "manual"; c.end = now;
      s.cycles.push({id: nextCycle++, start: now, end: nextB(s, now), closed: false, rx: 0, tx: 0, quota_gb: s.quota_gb, billing: s.billing});
      return R(200, {ok: true});
    }
    if (sub === "token" && method === "POST") { s.token = tok(); return R(200, {token: s.token}); }
    return R(405, {error: "method not allowed"});
  }
  const today0 = now => dayStart(now);
  function parseRange(qs, now) {
    if (qs.get("start") && qs.get("end")) {
      const a = fromIso(qs.get("start")), b = fromIso(qs.get("end"));
      if (b < a) throw new Error("结束日期不能早于开始日期");
      const days = Math.round((b - a) / D) + 1;
      if (days > 400) throw new Error("区间最长 400 天");
      return [a, days];
    }
    const days = Math.max(1, Math.min(+(qs.get("days") || 30), 400));
    return [today0(now) - (days - 1) * D, days];
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, opt = {}) => {
    const u = new URL(typeof input === "string" ? input : input.url, location.href);
    if (!u.pathname.startsWith("/api/")) return realFetch(input, opt);
    let body = opt.body;
    if (typeof body === "string") { try { body = JSON.parse(body); } catch { body = {}; } }
    await new Promise(r => setTimeout(r, 60 + Math.random() * 120));
    try { return await handle(u.pathname, (opt.method || "GET").toUpperCase(), body || {}, u.searchParams); }
    catch (e) { return R(400, {error: e.message}); }
  };

  // 下载备份在演示站改为提示
  document.addEventListener("click", e => {
    const a = e.target.closest && e.target.closest('a[href="/api/backup"]');
    if (a) { e.preventDefault(); if (typeof toast === "function") toast("演示站不提供下载，正式部署后即可下载备份"); }
  }, true);
})();
