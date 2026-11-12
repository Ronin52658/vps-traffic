#!/usr/bin/env python3
"""
VPS 流量监控面板 - 服务端（仅用 Python 标准库，Python 3.9+）

环境变量：
  VT_PASSWORD    启动时把面板密码重设为此值（一般不用设，首次启动会自动生成）
  VT_PORT        监听端口，默认 8080
  VT_LISTEN      监听地址，默认 0.0.0.0
  VT_DB          SQLite 路径，默认与本文件同目录的 traffic.db
  VT_TZ          计算日统计与重置点的时区，默认 Asia/Shanghai
  VT_PUBLIC_URL  面板对外地址，例如 https://traffic.example.com。设置后只接受 Host 为该域名的请求
  VT_REQUIRE_HTTPS 默认 1：只接受经信任反代（VT_TRUSTED_PROXIES）转发、且 X-Forwarded-Proto 为 https
                 的请求，直接用 http://IP:端口 访问一律拒绝（网页和 Agent 上报都是）。
                 设为 0 可临时关闭（不建议）
  VT_AGENT_REPO / VT_AGENT_COMMIT / VT_AGENT_INSTALL_SHA256
                 覆盖 agent_pin.json：Agent 安装脚本所在的 GitHub 仓库、固定提交和 install.sh 的 SHA256
  VT_TG_TOKEN    Telegram Bot Token（可选，建议写在 /etc/vps-traffic-panel.env，权限 600）
  VT_TG_CHAT     Telegram Chat ID（可选）
  VT_SESSION_DAYS 登录保持天数，默认 30；期间每天首次访问会自动续期
  VT_TRUSTED_PROXIES 信任的反代地址（逗号分隔的 IP 或网段），只有来自这些地址的请求才读取
                 X-Forwarded-For / X-Real-IP。默认 127.0.0.1,::1；
                 Docker 里的 Nginx Proxy Manager 一般填 172.16.0.0/12

命令行：
  python3 server.py --set-password 新密码   重设面板密码（之后重启服务）
  python3 server.py --set-password -       从标准输入读取新密码（不会出现在进程列表里）
"""
import calendar
import collections
import hashlib
import hmac
import json
import os
import ipaddress
import re
import secrets
import shutil
import sys
import sqlite3
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("VT_DB", os.path.join(BASE, "traffic.db"))
LISTEN = os.environ.get("VT_LISTEN", "0.0.0.0")
PORT = int(os.environ.get("VT_PORT", "8080"))
TZ_NAME = os.environ.get("VT_TZ", "Asia/Shanghai")
PUBLIC_URL = os.environ.get("VT_PUBLIC_URL", "").rstrip("/")
REQUIRE_HTTPS = os.environ.get("VT_REQUIRE_HTTPS", "1").strip() != "0"
PUBLIC_HOST = urllib.parse.urlparse(PUBLIC_URL).netloc.lower() if PUBLIC_URL else ""
HSTS_MAX_AGE = 31536000         # 浏览器记住一年：之后自动只用 HTTPS 访问该域名
TG_TOKEN = os.environ.get("VT_TG_TOKEN", "")
TG_CHAT = os.environ.get("VT_TG_CHAT", "")

METRICS_KEEP_DAYS = 7           # 系统监控（CPU/内存等）分钟数据保留天数
HOURLY_KEEP_DAYS = 400          # 小时明细保留天数；周期记录永久保留
OFFLINE_AFTER = 180             # 超过几秒没上报视为离线
MAX_DELTA = 50 * 1024 ** 4      # 单次上报上限 50 TiB，防止异常数据
ALERT_LEVELS = (80, 95, 100)
MAX_RESTORE = 1024 ** 3        # 还原档上限 1 GiB
KEEP_SAFETY_COPIES = 5         # 还原前自动保存的旧库份数
SESSION_TTL = int(os.environ.get("VT_SESSION_DAYS", "30")) * 86400   # 登录保持天数，期间有访问会自动续期
LOGIN_MAX_FAILS = 5             # 同一 IP 连续失败几次后锁定
LOGIN_LOCK_SEC = 900            # 锁定 15 分钟
GLOBAL_FAIL_WINDOW = 600        # 全局限流：10 分钟内
GLOBAL_FAIL_MAX = 30            # 所有 IP 合计失败这么多次，就暂停陌生 IP 的登录
GLOBAL_LOCK_SEC = 900           # 暂停 15 分钟；最近成功登录过的 IP 不受影响
MAX_QUOTA_GB = 1e7              # 额度上限（GB）
MAX_ORDER_IDS = 10000
MAX_CONNECTIONS = 200           # 同时处理的连接上限，超出的直接断开
REQUEST_TIMEOUT = 20            # 单个连接读写超时（秒），防止慢速连接占满线程
MAX_FAIL_ENTRIES = 10000        # 登录失败记录上限，防止内存无限增长
CSRF_HEADER = "X-VT-Request"    # 网页发出的改动请求必须带这个头，跨源页面无法伪造
# 还原备份时，这些设置沿用当前面板的值，不从备份里读（备份可能被人改过）
SECURITY_SETTINGS = ("secret", "password_hash", "revoked_sessions", "login_ips")
RESTORABLE_SETTINGS = ("interval", "idle_interval", "site_name", "theme")


def _parse_proxies(v):
    nets = []
    for part in (v or "").split(","):
        part = part.strip()
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                print(f"[warn] VT_TRUSTED_PROXIES 里的 {part} 无效，已忽略")
    return nets


TRUSTED_PROXIES = _parse_proxies(os.environ.get("VT_TRUSTED_PROXIES", "127.0.0.1,::1"))


def _load_agent_pin():
    """Agent 从 GitHub 固定提交安装：仓库、40 位提交哈希、install.sh 的 SHA256"""
    pin = {}
    try:
        with open(os.path.join(BASE, "agent_pin.json"), encoding="utf-8") as f:
            pin = json.load(f)
    except (OSError, ValueError) as e:
        print(f"[warn] 读取 agent_pin.json 失败：{e}")
    repo = os.environ.get("VT_AGENT_REPO") or pin.get("repo", "")
    commit = (os.environ.get("VT_AGENT_COMMIT") or pin.get("commit", "")).lower()
    sha = (os.environ.get("VT_AGENT_INSTALL_SHA256") or pin.get("install_sha256", "")).lower()
    if not (re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or "")
            and re.fullmatch(r"[0-9a-f]{40}", commit) and re.fullmatch(r"[0-9a-f]{64}", sha)):
        print("[warn] Agent 固定版本无效，面板不会生成安装命令（检查 agent_pin.json）")
        return None
    return {"repo": repo, "commit": commit, "install_sha256": sha}


AGENT_PIN = _load_agent_pin()
DEFAULT_INTERVAL = 3            # 有人在看面板时的上报/刷新间隔（秒）
DEFAULT_IDLE = 60               # 没人看面板时的上报间隔（秒），省流量
VIEW_ACTIVE_SEC = 90            # 最近这么久内有人访问面板，就算“有人在看”
REPORT_INTERVAL = DEFAULT_INTERVAL
IDLE_INTERVAL = DEFAULT_IDLE
LAST_VIEW = 0.0
MAX_RANGE_DAYS = 400            # 区间查询最长跨度，与小时明细保留天数一致

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo(TZ_NAME)
except Exception:
    print(f"[warn] 无法加载时区 {TZ_NAME}，改用 UTC+8")
    TZ = timezone(timedelta(hours=8))

DB_LOCK = threading.Lock()


# ---------------------------------------------------------------- 数据库

@contextmanager
def txn():
    """加锁 + 自动提交/回滚 + 关闭连接"""
    with DB_LOCK:
        conn = db()
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")   # WAL 下安全且快，适合每几秒一次的上报
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA trusted_schema=OFF")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS servers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  quota_gb REAL NOT NULL DEFAULT 0,
  billing TEXT NOT NULL DEFAULT 'sum',
  reset_type TEXT NOT NULL DEFAULT 'monthly',
  reset_day INTEGER NOT NULL DEFAULT 1,
  interval_days INTEGER NOT NULL DEFAULT 30,
  anchor TEXT,
  note TEXT NOT NULL DEFAULT '',
  sort INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL DEFAULT 0,
  rate_rx REAL NOT NULL DEFAULT 0,
  rate_tx REAL NOT NULL DEFAULT 0,
  iface TEXT NOT NULL DEFAULT '',
  hostname TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS traffic_hourly(
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  rx INTEGER NOT NULL DEFAULT 0,
  tx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(server_id, ts)
);
CREATE TABLE IF NOT EXISTS cycles(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  start_ts INTEGER NOT NULL,
  end_ts INTEGER,
  rx INTEGER NOT NULL DEFAULT 0,
  tx INTEGER NOT NULL DEFAULT 0,
  quota_gb REAL NOT NULL DEFAULT 0,
  billing TEXT NOT NULL DEFAULT 'sum',
  closed INTEGER NOT NULL DEFAULT 0,
  closed_at INTEGER,
  closed_reason TEXT,
  alert_level INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cycles_srv ON cycles(server_id, closed, start_ts);
CREATE TABLE IF NOT EXISTS metrics_minute(
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  cpu_sum REAL NOT NULL DEFAULT 0,
  n INTEGER NOT NULL DEFAULT 0,
  load1 REAL, mem_used INTEGER, mem_total INTEGER, swap_used INTEGER, swap_total INTEGER,
  disk_used INTEGER, disk_total INTEGER, tcp INTEGER, udp INTEGER, procs INTEGER,
  rx INTEGER NOT NULL DEFAULT 0,
  tx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(server_id, ts)
);
"""

# 旧版数据库或旧备份缺的字段，启动和还原时自动补上
SERVER_COLUMNS = {
    "metrics": "TEXT NOT NULL DEFAULT ''",
    "sysinfo": "TEXT NOT NULL DEFAULT ''",
    "public_ip": "TEXT NOT NULL DEFAULT ''",
    "country": "TEXT NOT NULL DEFAULT ''",
    "geo_ip": "TEXT NOT NULL DEFAULT ''",
    "geo_country": "TEXT NOT NULL DEFAULT ''",
}


def migrate(conn):
    conn.executescript(SCHEMA)
    have = {r[1] for r in conn.execute("PRAGMA table_info(servers)")}
    for col, decl in SERVER_COLUMNS.items():
        if col not in have:
            conn.execute(f"ALTER TABLE servers ADD COLUMN {col} {decl}")
    # 旧版允许填 Infinity 之类的额度，会让网页解析失败：改成不限额
    for t in ("servers", "cycles"):
        conn.execute(f"UPDATE {t} SET quota_gb=0 WHERE NOT (quota_gb BETWEEN 0 AND ?)", (MAX_QUOTA_GB,))


def get_setting(conn, k):
    r = conn.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return r["v"] if r else None


def set_setting(conn, k, v):
    conn.execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))


def hash_pw(pw, salt=None, it=200_000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), it).hex()
    return f"pbkdf2_sha256${it}${salt}${h}"


def verify_pw(pw, stored):
    try:
        _, it, salt, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), int(it)).hex()
        return hmac.compare_digest(calc, h)
    except Exception:
        return False


def init_db():
    """密码只以 PBKDF2 哈希保存在数据库"""
    global SECRET
    with txn() as conn:
        migrate(conn)
        SECRET = get_setting(conn, "secret")
        if not SECRET:
            SECRET = secrets.token_hex(32)
            set_setting(conn, "secret", SECRET)
        env_pw = os.environ.get("VT_PASSWORD")
        legacy = get_setting(conn, "password")          # 旧版明文密码，迁移成哈希
        if env_pw:
            set_setting(conn, "password_hash", hash_pw(env_pw))
        elif not get_setting(conn, "password_hash"):
            pw = legacy or secrets.token_urlsafe(12)
            set_setting(conn, "password_hash", hash_pw(pw))
            if not legacy:
                print(f"[init] 已生成面板密码：{pw}")
        conn.execute("DELETE FROM settings WHERE k='password'")
    load_interval()
    load_revoked()


def _clamp(v, default):
    try:
        return min(300, max(1, int(v)))
    except (TypeError, ValueError):
        return default


def load_interval():
    global REPORT_INTERVAL, IDLE_INTERVAL
    with txn() as conn:
        REPORT_INTERVAL = _clamp(get_setting(conn, "interval"), DEFAULT_INTERVAL)
        IDLE_INTERVAL = _clamp(get_setting(conn, "idle_interval"), DEFAULT_IDLE)


DEFAULT_SITE_NAME = "VPS 流量"


def get_site_name():
    with txn() as conn:
        return get_setting(conn, "site_name") or DEFAULT_SITE_NAME


THEMES = ("system", "light", "dark")


def get_theme():
    with txn() as conn:
        t = get_setting(conn, "theme")
    return t if t in THEMES else "system"


def set_site_name(name):
    name = re.sub(r"[\x00-\x1f<>]", "", str(name)).strip()
    if not 1 <= len(name) <= 40:
        raise ValueError("面板名称须为 1–40 个字符")
    with txn() as conn:
        set_setting(conn, "site_name", name)


def set_intervals(live=None, idle=None):
    vals = {}
    for key, v in (("interval", live), ("idle_interval", idle)):
        if v is None:
            continue
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise ValueError("间隔须为 1–300 的整数")
        if not 1 <= n <= 300:
            raise ValueError("间隔须在 1–300 秒")
        vals[key] = n
    with txn() as conn:
        for k, n in vals.items():
            set_setting(conn, k, str(n))
    load_interval()


def current_interval():
    """有人在看面板时用实时间隔，否则用空闲间隔"""
    if time.time() - LAST_VIEW < VIEW_ACTIVE_SEC:
        return REPORT_INTERVAL
    return max(REPORT_INTERVAL, IDLE_INTERVAL)


def set_password(new_pw):
    """改密码并轮换会话密钥，所有已登录的会话失效"""
    global SECRET
    with txn() as conn:
        set_setting(conn, "password_hash", hash_pw(new_pw))
        SECRET = secrets.token_hex(32)
        set_setting(conn, "secret", SECRET)
        set_setting(conn, "revoked_sessions", "{}")     # 换了密钥，旧会话本来就全部失效
    with _REVOKED_LOCK:
        _REVOKED.clear()


def check_password(pw):
    with txn() as conn:
        stored = get_setting(conn, "password_hash") or ""
    return verify_pw(pw, stored)


# 登录失败限流：ip -> [失败次数, 首次失败时间, 锁定到期]
_FAILS = {}
_FAILS_LOCK = threading.Lock()


_GLOBAL_FAILS = collections.deque()
_GLOBAL_LOCK_UNTIL = 0.0
TRUSTED_LOGIN_DAYS = 30


def _trusted_ips():
    """最近 30 天成功登录过的 IP：{ip: 时间戳}，存库，重启后仍有效"""
    with txn() as conn:
        try:
            d = json.loads(get_setting(conn, "login_ips") or "{}")
        except ValueError:
            d = {}
    cut = time.time() - TRUSTED_LOGIN_DAYS * 86400
    return {k: v for k, v in d.items() if v > cut}


def login_locked(ip):
    """返回需要等待的秒数；0 表示可以尝试"""
    now = time.time()
    with _FAILS_LOCK:
        r = _FAILS.get(ip)
        left = int(r[2] - now) if r else 0
        if left > 0:
            return left
        glob = int(_GLOBAL_LOCK_UNTIL - now)
    if glob > 0 and ip not in _trusted_ips():
        return glob
    return 0


def login_failed(ip):
    now = time.time()
    with _FAILS_LOCK:
        if ip not in _FAILS and len(_FAILS) >= MAX_FAIL_ENTRIES:
            prune_fails(now)
            if len(_FAILS) >= MAX_FAIL_ENTRIES:              # 仍然满：丢掉最早的一条
                _FAILS.pop(min(_FAILS, key=lambda k: _FAILS[k][1]))
        r = _FAILS.setdefault(ip, [0, now, 0])
        if now - r[1] > LOGIN_LOCK_SEC:
            r[:] = [0, now, 0]
        r[0] += 1
        if r[0] >= LOGIN_MAX_FAILS:
            r[:] = [0, now, now + LOGIN_LOCK_SEC]
            print(f"[auth] {ip} 连续登录失败，锁定 {LOGIN_LOCK_SEC // 60} 分钟")
        # 全局：防止换很多 IP 轮流猜密码
        global _GLOBAL_LOCK_UNTIL
        _GLOBAL_FAILS.append(now)
        while _GLOBAL_FAILS and _GLOBAL_FAILS[0] < now - GLOBAL_FAIL_WINDOW:
            _GLOBAL_FAILS.popleft()
        if len(_GLOBAL_FAILS) >= GLOBAL_FAIL_MAX and _GLOBAL_LOCK_UNTIL < now:
            _GLOBAL_LOCK_UNTIL = now + GLOBAL_LOCK_SEC
            _GLOBAL_FAILS.clear()
            print(f"[auth] {GLOBAL_FAIL_WINDOW // 60} 分钟内登录失败 {GLOBAL_FAIL_MAX} 次，"
                  f"暂停陌生 IP 登录 {GLOBAL_LOCK_SEC // 60} 分钟")


def prune_fails(now):
    """清掉已经过期的失败记录（调用方持有 _FAILS_LOCK）"""
    for k in [k for k, r in _FAILS.items() if r[2] < now and now - r[1] > LOGIN_LOCK_SEC]:
        del _FAILS[k]


def login_ok(ip):
    with _FAILS_LOCK:
        _FAILS.pop(ip, None)
    d = _trusted_ips()
    d[ip] = time.time()
    d = dict(sorted(d.items(), key=lambda kv: kv[1])[-50:])   # 最多记 50 个
    with txn() as conn:
        set_setting(conn, "login_ips", json.dumps(d))


# ---------------------------------------------------------------- 周期计算

def local_midnight(d: date) -> int:
    return int(datetime(d.year, d.month, d.day, tzinfo=TZ).timestamp())


def month_boundary(y, m, day) -> int:
    last = calendar.monthrange(y, m)[1]
    return local_midnight(date(y, m, min(day, last)))


def shift_month(y, m, n):
    m0 = y * 12 + (m - 1) + n
    return m0 // 12, m0 % 12 + 1


def anchor_date(srv) -> date:
    try:
        return date.fromisoformat(srv["anchor"])
    except Exception:
        return datetime.fromtimestamp(srv["created_at"], TZ).date()


def next_boundary(srv, after_ts):
    """严格大于 after_ts 的下一个重置点；手动模式返回 None"""
    t = srv["reset_type"]
    if t == "monthly":
        dt = datetime.fromtimestamp(after_ts, TZ)
        for i in range(0, 3):
            y, m = shift_month(dt.year, dt.month, i)
            b = month_boundary(y, m, srv["reset_day"])
            if b > after_ts:
                return b
    elif t == "interval":
        n = max(1, int(srv["interval_days"]))
        a = anchor_date(srv)
        cur = datetime.fromtimestamp(after_ts, TZ).date()
        k = (cur - a).days // n
        for j in (k, k + 1, k + 2):
            b = local_midnight(a + timedelta(days=j * n))
            if b > after_ts:
                return b
    return None


def prev_boundary(srv, ts):
    """小于等于 ts 的最近重置点；手动模式返回 None"""
    t = srv["reset_type"]
    if t == "monthly":
        dt = datetime.fromtimestamp(ts, TZ)
        for i in range(0, -3, -1):
            y, m = shift_month(dt.year, dt.month, i)
            b = month_boundary(y, m, srv["reset_day"])
            if b <= ts:
                return b
    elif t == "interval":
        n = max(1, int(srv["interval_days"]))
        a = anchor_date(srv)
        cur = datetime.fromtimestamp(ts, TZ).date()
        k = (cur - a).days // n
        for j in (k + 1, k, k - 1):
            b = local_midnight(a + timedelta(days=j * n))
            if b <= ts:
                return b
    return None


def billed(rx, tx, mode):
    if mode == "out":
        return tx
    if mode == "in":
        return rx
    if mode == "max":
        return max(rx, tx)
    return rx + tx


def open_cycle(conn, srv, start_ts):
    cur = conn.execute(
        "INSERT INTO cycles(server_id,start_ts,end_ts,quota_gb,billing) VALUES(?,?,?,?,?)",
        (srv["id"], start_ts, next_boundary(srv, start_ts), srv["quota_gb"], srv["billing"]))
    return conn.execute("SELECT * FROM cycles WHERE id=?", (cur.lastrowid,)).fetchone()


def close_cycle(conn, cyc, reason, at):
    conn.execute("UPDATE cycles SET closed=1, closed_at=?, closed_reason=?, end_ts=COALESCE(end_ts, ?) WHERE id=?",
                 (at, reason, at, cyc["id"]))


def ensure_cycle(conn, srv, now=None):
    """取得当前周期，必要时自动滚动到新周期（旧周期保留）"""
    now = now or int(time.time())
    c = conn.execute("SELECT * FROM cycles WHERE server_id=? AND closed=0 ORDER BY id DESC LIMIT 1",
                     (srv["id"],)).fetchone()
    if c is None:
        start = prev_boundary(srv, now)
        return open_cycle(conn, srv, start if start is not None else now)
    guard = 0
    while c["end_ts"] is not None and now >= c["end_ts"] and guard < 500:
        close_cycle(conn, c, "auto", c["end_ts"])
        c = open_cycle(conn, srv, c["end_ts"])
        guard += 1
    return c


# ---------------------------------------------------------------- 通知

def tg_send(text):
    if not (TG_TOKEN and TG_CHAT):
        return

    def run():
        try:
            data = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": text}).encode()
            urllib.request.urlopen(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", data, timeout=10)
        except Exception as e:
            print(f"[tg] 发送失败：{e}")
    threading.Thread(target=run, daemon=True).start()


def fmt_bytes(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.2f} {u}"
        n /= 1024


def check_alert(conn, srv, cyc):
    q = cyc["quota_gb"]
    if q <= 0:
        return
    used = billed(cyc["rx"], cyc["tx"], cyc["billing"])
    pct = used / (q * 1024 ** 3) * 100
    level = max([lv for lv in ALERT_LEVELS if pct >= lv], default=0)
    if level > cyc["alert_level"]:
        conn.execute("UPDATE cycles SET alert_level=? WHERE id=?", (level, cyc["id"]))
        tg_send(f"⚠️ {srv['name']} 本周期流量已用 {pct:.1f}%\n"
                f"已用 {fmt_bytes(used)} / 额度 {q:g} GB")


# ---------------------------------------------------------------- 业务逻辑

# 每台服务器上次上报的精确时间（内存），用来算实时网速
LAST_REPORT = {}
# 每台服务器最近的原始采样（内存），给“实时”图表用
RECENT = collections.defaultdict(lambda: collections.deque(maxlen=240))


def _num(v, lo=0.0, hi=1e18):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if lo <= f <= hi and f == f else None


def _clamp_pct(v):
    """CPU 百分比：iowait 计数偶尔倒退会算出 <0 或 >100，夹到 0–100 而不是丢弃"""
    f = _num(v, -1e6, 1e6)
    return None if f is None else min(100.0, max(0.0, f))


def parse_sys(d):
    """校验 Agent 送来的系统指标；格式不对的字段丢弃"""
    if not isinstance(d, dict):
        return None
    load = d.get("load") if isinstance(d.get("load"), list) else []
    mem = d.get("mem") if isinstance(d.get("mem"), list) else []
    disk = d.get("disk") if isinstance(d.get("disk"), list) else []
    g = lambda arr, i: _num(arr[i]) if len(arr) > i else None
    out = {
        "cpu": _clamp_pct(d.get("cpu")),
        "load": [g(load, i) for i in range(3)],
        "mem_total": g(mem, 0), "mem_used": g(mem, 1), "swap_total": g(mem, 2), "swap_used": g(mem, 3),
        "disk_total": g(disk, 0), "disk_used": g(disk, 1),
        "tcp": _num(d.get("tcp"), 0, 1e7), "udp": _num(d.get("udp"), 0, 1e7),
        "procs": _num(d.get("procs"), 0, 1e7), "uptime": _num(d.get("uptime"), 0, 1e10),
    }
    for k in ("mem_total", "mem_used", "swap_total", "swap_used", "disk_total", "disk_used", "tcp", "udp", "procs", "uptime"):
        if out[k] is not None:
            out[k] = int(out[k])
    return out


# ---- 按 IP 自动识别国家/地区（面板首次看到某个 IP 时查一次，结果存库）
_GEO_BUSY = set()
_GEO_FAIL = {}          # ip -> 下次可重试的时间


def _geo_query(ip):
    """依次尝试两个免费接口（都走 HTTPS），返回两位国家代码或空字符串"""
    for url, is_json in ((f"https://ipinfo.io/{ip}/country", False), (f"https://api.country.is/{ip}", True)):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vps-traffic-panel"})
            with urllib.request.urlopen(req, timeout=6) as r:
                raw = r.read(512).decode("ascii", "ignore")
            cc = (json.loads(raw).get("country") or "") if is_json else raw
            cc = str(cc).strip().upper()
            if re.fullmatch(r"[A-Z]{2}", cc):
                return cc
        except Exception:
            continue
    return ""


def geo_lookup_async(sid, ip):
    try:
        if not ipaddress.ip_address(ip).is_global:
            return
    except ValueError:
        return
    if ip in _GEO_BUSY or _GEO_FAIL.get(ip, 0) > time.time():
        return
    _GEO_BUSY.add(ip)

    def run():
        try:
            cc = _geo_query(ip)
            if cc:
                with txn() as conn:
                    conn.execute("UPDATE servers SET geo_ip=?, geo_country=? WHERE id=?", (ip, cc, sid))
            else:
                _GEO_FAIL[ip] = time.time() + 3600
        finally:
            _GEO_BUSY.discard(ip)
    threading.Thread(target=run, daemon=True).start()


def parse_info(d):
    if not isinstance(d, dict):
        return None
    txt = lambda k, n=120: re.sub(r"[\x00-\x1f]", "", str(d.get(k, "")))[:n]
    cores = _num(d.get("cores"), 0, 100000)
    return {"os": txt("os"), "kernel": txt("kernel"), "arch": txt("arch", 32), "cpu_model": txt("cpu_model"),
            "cores": int(cores) if cores is not None else 0, "virt": txt("virt", 32)}


def handle_report(token, body, ip=""):
    try:
        rx = int(body.get("rx", 0))
        tx = int(body.get("tx", 0))
    except (TypeError, ValueError):
        return 400, {"error": "bad payload"}
    if rx < 0 or tx < 0 or rx > MAX_DELTA or tx > MAX_DELTA:
        return 400, {"error": "delta out of range"}
    iface = str(body.get("iface", ""))[:32]
    host = str(body.get("hostname", ""))[:64]
    now = int(time.time())
    hour = now - now % 3600
    with txn() as conn:
        srv = conn.execute("SELECT * FROM servers WHERE token=?", (token,)).fetchone()
        if srv is None:
            return 401, {"error": "invalid token"}
        conn.execute("""INSERT INTO traffic_hourly(server_id,ts,rx,tx) VALUES(?,?,?,?)
                        ON CONFLICT(server_id,ts) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx""",
                     (srv["id"], hour, rx, tx))
        cyc = ensure_cycle(conn, srv, now)
        conn.execute("UPDATE cycles SET rx=rx+?, tx=tx+? WHERE id=?", (rx, tx, cyc["id"]))
        t = time.time()
        gap = t - LAST_REPORT.get(srv["id"], srv["last_seen"])
        LAST_REPORT[srv["id"]] = t
        rr, rt = (rx / gap, tx / gap) if 0.5 <= gap <= 600 else (0, 0)
        conn.execute("UPDATE servers SET last_seen=?, rate_rx=?, rate_tx=?, iface=?, hostname=?, public_ip=? WHERE id=?",
                     (now, rr, rt, iface, host, ip[:64], srv["id"]))
        if ip and ip != srv["geo_ip"]:
            geo_lookup_async(srv["id"], ip)
        sysd = parse_sys(body.get("sys"))
        if sysd:
            conn.execute("UPDATE servers SET metrics=? WHERE id=?", (json.dumps(sysd), srv["id"]))
            m = now - now % 60
            conn.execute("""INSERT INTO metrics_minute(server_id,ts,cpu_sum,n,load1,mem_used,mem_total,swap_used,swap_total,
                              disk_used,disk_total,tcp,udp,procs,rx,tx) VALUES(?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?)
                            ON CONFLICT(server_id,ts) DO UPDATE SET cpu_sum=cpu_sum+excluded.cpu_sum, n=n+1,
                              load1=excluded.load1, mem_used=excluded.mem_used, mem_total=excluded.mem_total,
                              swap_used=excluded.swap_used, swap_total=excluded.swap_total, disk_used=excluded.disk_used,
                              disk_total=excluded.disk_total, tcp=excluded.tcp, udp=excluded.udp, procs=excluded.procs,
                              rx=rx+excluded.rx, tx=tx+excluded.tx""",
                         (srv["id"], m, sysd["cpu"] or 0, sysd["load"][0], sysd["mem_used"], sysd["mem_total"],
                          sysd["swap_used"], sysd["swap_total"], sysd["disk_used"], sysd["disk_total"],
                          sysd["tcp"], sysd["udp"], sysd["procs"], rx, tx))
            RECENT[srv["id"]].append({"ts": round(t, 1), "cpu": sysd["cpu"], "load1": sysd["load"][0],
                                      "mem_used": sysd["mem_used"], "mem_total": sysd["mem_total"],
                                      "swap_used": sysd["swap_used"], "swap_total": sysd["swap_total"],
                                      "disk_used": sysd["disk_used"], "disk_total": sysd["disk_total"],
                                      "rx_rate": rr, "tx_rate": rt, "tcp": sysd["tcp"], "udp": sysd["udp"],
                                      "procs": sysd["procs"]})
        info = parse_info(body.get("info"))
        if info:
            conn.execute("UPDATE servers SET sysinfo=? WHERE id=?", (json.dumps(info, ensure_ascii=False), srv["id"]))
        cyc = conn.execute("SELECT * FROM cycles WHERE id=?", (cyc["id"],)).fetchone()
        check_alert(conn, srv, cyc)
    return 200, {"ok": True, "interval": current_interval()}   # Agent 按这个值调整上报间隔


def today_start(now):
    return local_midnight(datetime.fromtimestamp(now, TZ).date())


def _loads(v):
    try:
        return json.loads(v) if v else None
    except ValueError:
        return None


def server_summary(conn, srv, now):
    cyc = ensure_cycle(conn, srv, now)
    t0 = today_start(now)
    td = conn.execute("SELECT COALESCE(SUM(rx),0) rx, COALESCE(SUM(tx),0) tx FROM traffic_hourly "
                      "WHERE server_id=? AND ts>=?", (srv["id"], t0)).fetchone()
    online = now - srv["last_seen"] <= OFFLINE_AFTER
    return {
        "id": srv["id"], "name": srv["name"], "note": srv["note"],
        "quota_gb": srv["quota_gb"], "billing": srv["billing"],
        "reset_type": srv["reset_type"], "reset_day": srv["reset_day"],
        "interval_days": srv["interval_days"], "anchor": srv["anchor"] or anchor_date(srv).isoformat(),
        "online": online, "last_seen": srv["last_seen"],
        "rate_rx": srv["rate_rx"] if online else 0, "rate_tx": srv["rate_tx"] if online else 0,
        "iface": srv["iface"], "hostname": srv["hostname"],
        "ip": srv["public_ip"], "country": srv["country"] or srv["geo_country"],
        "country_manual": srv["country"], "country_auto": srv["geo_country"],
        "sys": _loads(srv["metrics"]), "info": _loads(srv["sysinfo"]),
        "today": {"rx": td["rx"], "tx": td["tx"]},
        "cycle": {"id": cyc["id"], "start": cyc["start_ts"], "end": cyc["end_ts"],
                  "rx": cyc["rx"], "tx": cyc["tx"], "used": billed(cyc["rx"], cyc["tx"], srv["billing"])},
    }


METRIC_RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400}


def metrics_series(conn, sid, rng, now):
    """实时：内存里的原始采样；其他：分钟数据按区间分桶，最多约 240 个点"""
    if rng == "live" or rng not in METRIC_RANGES:
        pts = list(RECENT.get(sid, []))
        if pts:
            return pts
        rng = "1h"
    span = METRIC_RANGES[rng]
    bucket = max(60, (span // 240) // 60 * 60)
    rows = conn.execute(f"""
        SELECT (ts / {bucket}) * {bucket} AS b, SUM(cpu_sum) / MAX(SUM(n), 1) AS cpu, AVG(load1) AS load1,
               AVG(mem_used) AS mem_used, MAX(mem_total) AS mem_total, AVG(swap_used) AS swap_used,
               MAX(swap_total) AS swap_total, AVG(disk_used) AS disk_used, MAX(disk_total) AS disk_total,
               AVG(tcp) AS tcp, AVG(udp) AS udp, AVG(procs) AS procs,
               SUM(rx) * 1.0 / (COUNT(*) * 60) AS rx_rate, SUM(tx) * 1.0 / (COUNT(*) * 60) AS tx_rate
        FROM metrics_minute WHERE server_id=? AND ts>=? GROUP BY b ORDER BY b""", (sid, now - span)).fetchall()
    return [{"ts": r["b"], **{k: r[k] for k in r.keys() if k != "b"}} for r in rows]


def parse_range(qs, now):
    """start/end 为 YYYY-MM-DD（含首尾两天）；没给时用 days 往回推"""
    if qs.get("start") and qs.get("end"):
        start_d = date.fromisoformat(qs["start"][0])
        end_d = date.fromisoformat(qs["end"][0])
        if end_d < start_d:
            raise ValueError("结束日期不能早于开始日期")
        if (end_d - start_d).days + 1 > MAX_RANGE_DAYS:
            raise ValueError(f"区间最长 {MAX_RANGE_DAYS} 天")
        return start_d, end_d
    days = max(1, min(int(qs.get("days", ["30"])[0]), MAX_RANGE_DAYS))
    end_d = datetime.fromtimestamp(now, TZ).date()
    return end_d - timedelta(days=days - 1), end_d


def range_totals(conn, start_d, end_d):
    t0, t1 = local_midnight(start_d), local_midnight(end_d + timedelta(days=1))
    rows = conn.execute("SELECT server_id, COALESCE(SUM(rx),0) rx, COALESCE(SUM(tx),0) tx FROM traffic_hourly "
                        "WHERE ts>=? AND ts<? GROUP BY server_id", (t0, t1)).fetchall()
    sums = {r["server_id"]: (r["rx"], r["tx"]) for r in rows}
    out = []
    for srv in conn.execute("SELECT id, name, billing FROM servers ORDER BY sort, id").fetchall():
        rx, tx = sums.get(srv["id"], (0, 0))
        out.append({"id": srv["id"], "name": srv["name"], "billing": srv["billing"],
                    "rx": rx, "tx": tx, "used": billed(rx, tx, srv["billing"])})
    return out


def daily_stats(conn, sid, start_d, end_d):
    days = (end_d - start_d).days + 1
    rows = conn.execute("SELECT ts, rx, tx FROM traffic_hourly WHERE server_id=? AND ts>=? AND ts<?",
                        (sid, local_midnight(start_d), local_midnight(end_d + timedelta(days=1)))).fetchall()
    agg = {}
    for r in rows:
        d = datetime.fromtimestamp(r["ts"], TZ).date().isoformat()
        a = agg.setdefault(d, [0, 0])
        a[0] += r["rx"]
        a[1] += r["tx"]
    out = []
    for i in range(days):
        d = (start_d + timedelta(days=i)).isoformat()
        rx, tx = agg.get(d, (0, 0))
        out.append({"date": d, "rx": rx, "tx": tx})
    return out


def hourly_stats(conn, sid, day_str):
    d = date.fromisoformat(day_str)
    t0 = local_midnight(d)
    t1 = local_midnight(d + timedelta(days=1))
    rows = conn.execute("SELECT ts, rx, tx FROM traffic_hourly WHERE server_id=? AND ts>=? AND ts<?",
                        (sid, t0, t1)).fetchall()
    agg = {}
    for r in rows:
        h = datetime.fromtimestamp(r["ts"], TZ).hour
        a = agg.setdefault(h, [0, 0])
        a[0] += r["rx"]
        a[1] += r["tx"]
    return [{"hour": h, "rx": agg.get(h, (0, 0))[0], "tx": agg.get(h, (0, 0))[1]} for h in range(24)]


VALID_BILLING = {"sum", "out", "in", "max"}
VALID_RESET = {"monthly", "interval", "manual"}


def clean_server_input(b, partial=False):
    out = {}
    if "name" in b or not partial:
        name = str(b.get("name", "")).strip()[:64]
        if not name:
            raise ValueError("名称不能为空")
        out["name"] = name
    if "note" in b:
        out["note"] = str(b["note"])[:200]
    if "quota_gb" in b or not partial:
        q = float(b.get("quota_gb") or 0)
        if not 0 <= q <= MAX_QUOTA_GB:          # 也挡掉 NaN / Infinity（会让网页无法解析数据）
            raise ValueError(f"额度须在 0–{MAX_QUOTA_GB:g} GB")
        out["quota_gb"] = q
    if "billing" in b or not partial:
        v = b.get("billing", "sum")
        if v not in VALID_BILLING:
            raise ValueError("计费方式无效")
        out["billing"] = v
    if "reset_type" in b or not partial:
        v = b.get("reset_type", "monthly")
        if v not in VALID_RESET:
            raise ValueError("重置方式无效")
        out["reset_type"] = v
    if "reset_day" in b or not partial:
        d = int(b.get("reset_day") or 1)
        if not 1 <= d <= 31:
            raise ValueError("重置日须在 1–31")
        out["reset_day"] = d
    if "interval_days" in b or not partial:
        n = int(b.get("interval_days") or 30)
        if not 1 <= n <= 3650:
            raise ValueError("间隔天数须在 1–3650")
        out["interval_days"] = n
    if "country" in b:
        c = str(b.get("country") or "").strip().upper()
        if c and not re.fullmatch(r"[A-Z]{2}", c):
            raise ValueError("地区请填两位国家代码，例如 SG、HK、US")
        out["country"] = c
    if "anchor" in b:
        a = b.get("anchor") or None
        if a:
            date.fromisoformat(a)
        out["anchor"] = a
    return out


def apply_rule_change(conn, sid, now):
    """规则变更后：当前周期保留起点，按新规则重算结束点"""
    srv = conn.execute("SELECT * FROM servers WHERE id=?", (sid,)).fetchone()
    cyc = ensure_cycle(conn, srv, now)
    # 额度或计费方式改了：告警等级按新额度重算，调高额度后到 80%/95%/100% 仍会提醒
    level = cyc["alert_level"]
    if srv["quota_gb"] > 0:
        pct = billed(cyc["rx"], cyc["tx"], srv["billing"]) / (srv["quota_gb"] * 1024 ** 3) * 100
        level = min(level, max([lv for lv in ALERT_LEVELS if pct >= lv], default=0))
    else:
        level = 0
    conn.execute("UPDATE cycles SET end_ts=?, quota_gb=?, billing=?, alert_level=? WHERE id=?",
                 (next_boundary(srv, now), srv["quota_gb"], srv["billing"], level, cyc["id"]))
    ensure_cycle(conn, srv, now)


def maintenance_loop():
    last_ckpt = 0
    while True:
        try:
            now = int(time.time())
            with txn() as conn:
                for srv in conn.execute("SELECT * FROM servers").fetchall():
                    ensure_cycle(conn, srv, now)
                conn.execute("DELETE FROM traffic_hourly WHERE ts<?", (now - HOURLY_KEEP_DAYS * 86400,))
                conn.execute("DELETE FROM metrics_minute WHERE ts<?", (now - METRICS_KEEP_DAYS * 86400,))
            # 每小时收缩一次 WAL 文件并更新查询统计，长期运行也不会越来越大、越来越慢
            if now - last_ckpt >= 3600:
                with txn() as conn:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    conn.execute("PRAGMA optimize")
                last_ckpt = now
            with _FAILS_LOCK:
                prune_fails(time.time())
            for ip in [ip for ip, t in list(_GEO_FAIL.items()) if t < time.time()]:
                _GEO_FAIL.pop(ip, None)
            prune_revoked()
        except Exception as e:
            print(f"[maint] {e}")
        time.sleep(60)


# ---------------------------------------------------------------- 备份与还原

REQUIRED_TABLES = {
    "servers": {"id", "name", "token", "quota_gb", "billing", "reset_type", "reset_day", "interval_days", "created_at"},
    "cycles": {"id", "server_id", "start_ts", "end_ts", "rx", "tx", "closed"},
    "traffic_hourly": {"server_id", "ts", "rx", "tx"},
}


def copy_db(src_conn, dst_path):
    """用 SQLite 在线备份 API 复制，并转成独立的单文件（非 WAL）"""
    dst = sqlite3.connect(dst_path)
    try:
        src_conn.backup(dst)
        dst.execute("PRAGMA journal_mode=DELETE")
    finally:
        dst.close()


def export_backup():
    """生成一份一致的数据库快照，返回临时文件路径（调用方负责删除）"""
    fd, path = tempfile.mkstemp(prefix="vt-export-", suffix=".db", dir=os.path.dirname(DB_PATH) or ".")
    os.close(fd)
    with DB_LOCK:
        conn = db()
        try:
            copy_db(conn, path)
        finally:
            conn.close()
    # 备份里去掉会话密钥、密码哈希、登录白名单和吊销表：拿到备份文件的人不能伪造登录，
    # 也不能离线破解密码（还原时这些本来就沿用当前面板的值）
    out = sqlite3.connect(path)
    try:
        ph = ",".join("?" * len(SECURITY_SETTINGS))
        out.execute(f"DELETE FROM settings WHERE k IN ({ph})", SECURITY_SETTINGS)
        out.commit()
        out.execute("VACUUM")               # 删掉的内容不残留在文件空闲页里
    finally:
        out.close()
    return path


def validate_backup(path):
    with open(path, "rb") as f:
        if f.read(16) != b"SQLite format 3\x00":
            raise ValueError("这不是 SQLite 数据库文件")
    c = sqlite3.connect(path)
    try:
        if c.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("备份文件已损坏（完整性检查未通过）")
        c.execute("PRAGMA trusted_schema=OFF")
        kinds = dict(c.execute("SELECT name, type FROM sqlite_master"))
        for table, cols in REQUIRED_TABLES.items():
            if kinds.get(table) != "table":
                raise ValueError(f"缺少数据表 {table}，这不是本面板的备份")
            have = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
            if not have:
                raise ValueError(f"缺少数据表 {table}，这不是本面板的备份")
            missing = cols - have
            if missing:
                raise ValueError(f"数据表 {table} 缺少字段：{', '.join(sorted(missing))}")
        return {
            "servers": c.execute("SELECT COUNT(*) FROM servers").fetchone()[0],
            "cycles": c.execute("SELECT COUNT(*) FROM cycles").fetchone()[0],
            "hourly": c.execute("SELECT COUNT(*) FROM traffic_hourly").fetchone()[0],
        }
    finally:
        c.close()


def prune_safety_copies():
    d = os.path.dirname(DB_PATH) or "."
    base = os.path.basename(DB_PATH) + ".before-restore-"
    old = sorted(f for f in os.listdir(d) if f.startswith(base))
    for f in old[:-KEEP_SAFETY_COPIES]:
        try:
            os.remove(os.path.join(d, f))
        except OSError:
            pass


def restore_backup(upload_path):
    """先验证，再保存当前库，最后用备份覆盖当前库；登录密码与会话密钥保持不变"""
    stats = validate_backup(upload_path)
    stamp = datetime.now(TZ).strftime("%Y%m%d-%H%M%S")
    safety = f"{DB_PATH}.before-restore-{stamp}"
    with DB_LOCK:
        live = db()
        try:
            keep = {k: get_setting(live, k) for k in SECURITY_SETTINGS}
            copy_db(live, safety)
            src = sqlite3.connect(upload_path)
            try:
                src.backup(live)
            finally:
                src.close()
            live.execute("PRAGMA journal_mode=WAL")
            # 备份里的触发器和视图一律删除：触发器能在下面写回密码时把它改掉
            for name, kind in live.execute(
                    "SELECT name, type FROM sqlite_master WHERE type IN ('trigger','view')").fetchall():
                live.execute(f'DROP {kind.upper()} IF EXISTS "{name.replace(chr(34), chr(34) * 2)}"')
            migrate(live)                       # 旧版本备份缺的表、字段或索引补上
            # 只保留可以从备份恢复的普通设置；密码、会话密钥、登录白名单沿用当前面板
            ph = ",".join("?" * len(RESTORABLE_SETTINGS))
            live.execute(f"DELETE FROM settings WHERE k NOT IN ({ph})", RESTORABLE_SETTINGS)
            keep["secret"] = SECRET
            for k, v in keep.items():
                if v is not None:
                    set_setting(live, k, v)
            left = live.execute("SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()[0]
            if left:
                raise RuntimeError("还原后仍有触发器或视图")
            live.commit()
        finally:
            live.close()
    prune_safety_copies()
    load_interval()
    stats["safety_copy"] = os.path.basename(safety)
    return stats


# ---------------------------------------------------------------- 认证

# 会话 Cookie：过期时间.会话ID.签名。续期时会话ID不变，退出登录时把会话ID记入吊销表，
# 这样退出后旧 Cookie（包括被偷走的副本）立即失效，续期也续不回来
_REVOKED = {}            # 会话ID -> 吊销记录保留到的时间
_REVOKED_LOCK = threading.Lock()


def _sign(exp, sid):
    return hmac.new(SECRET.encode(), f"{exp}.{sid}".encode(), hashlib.sha256).hexdigest()


def make_session(sid=None):
    sid = sid or secrets.token_hex(12)
    exp = int(time.time()) + SESSION_TTL
    return f"{exp}.{sid}.{_sign(exp, sid)}"


def parse_session(val):
    """有效时返回 (过期时间戳, 会话ID)，无效返回 None"""
    try:
        exp, sid, sig = val.split(".")
        if not re.fullmatch(r"[0-9a-f]{24}", sid):
            return None
        if hmac.compare_digest(sig, _sign(exp, sid)) and int(exp) > time.time():
            with _REVOKED_LOCK:
                if sid in _REVOKED:
                    return None
            return int(exp), sid
    except Exception:
        pass
    return None


def load_revoked():
    with txn() as conn:
        try:
            d = json.loads(get_setting(conn, "revoked_sessions") or "{}")
        except ValueError:
            d = {}
    with _REVOKED_LOCK:
        _REVOKED.clear()
        _REVOKED.update({k: v for k, v in d.items() if isinstance(v, (int, float))})


def _save_revoked():
    with _REVOKED_LOCK:
        data = json.dumps(_REVOKED)
    with txn() as conn:
        set_setting(conn, "revoked_sessions", data)


def revoke_session(sid):
    with _REVOKED_LOCK:
        _REVOKED[sid] = int(time.time()) + SESSION_TTL + 86400
    _save_revoked()


def prune_revoked():
    now = time.time()
    with _REVOKED_LOCK:
        old = [k for k, v in _REVOKED.items() if v < now]
        for k in old:
            del _REVOKED[k]
    if old:
        _save_revoked()


# ---------------------------------------------------------------- HTTP

FLAG_RE = re.compile(r"^/flags/([a-z]{2})\.png$")

STATIC = {"/": ("index.html", "text/html; charset=utf-8")}   # Agent 脚本改从 GitHub 固定提交下载

ROUTE_SRV = re.compile(r"^/api/servers/(\d+)(?:/(daily|hourly|cycles|reset|token|metrics))?$")


HOST_RE = re.compile(r"^[A-Za-z0-9.-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$")


class Handler(BaseHTTPRequestHandler):
    server_version = "VPSTraffic/1.0"
    timeout = REQUEST_TIMEOUT            # 慢速连接（只发半个请求）超时后断开

    def log_message(self, fmt, *args):
        pass

    def end_headers(self):
        if self.forwarded_https():
            self.send_header("Strict-Transport-Security", f"max-age={HSTS_MAX_AGE}")
        # 禁止被别的页面嵌入（防点击劫持）、禁止猜测类型、不外泄来源地址
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def transport_ok(self):
        """强制 HTTPS 反代：返回拒绝原因，空字符串表示放行"""
        if REQUIRE_HTTPS and not self.forwarded_https():
            if not self.from_proxy():
                return "面板只能通过 HTTPS 反代访问，不能直接用 IP:端口 访问"
            return "反代没有使用 HTTPS（X-Forwarded-Proto 不是 https）"
        if PUBLIC_HOST and (self.headers.get("Host") or "").lower() != PUBLIC_HOST:
            return f"请使用 {PUBLIC_URL} 访问"
        return ""

    def reject_transport(self, path, why):
        if path.startswith("/api/"):
            return self.send_json(403, {"error": why})
        link = f'<p><a href="{PUBLIC_URL}/">{PUBLIC_URL}</a></p>' if PUBLIC_URL else ""
        body = (f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
                f'<title>需要 HTTPS</title><body style="font:16px system-ui;padding:40px;max-width:640px">'
                f'<h2>需要 HTTPS</h2><p>{why}。</p>{link}</body>').encode()
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def csrf_ok(self):
        """改动类请求必须来自面板自己的网页：带自定义头（跨源页面带不了，除非通过预检，
        而面板不响应预检），且 Origin（浏览器会带）必须与 Host 一致"""
        if self.headers.get(CSRF_HEADER) != "1":
            return False
        origin = self.headers.get("Origin")
        if origin:
            return urllib.parse.urlparse(origin).netloc.lower() == (self.headers.get("Host") or "").lower()
        return True

    # ---- helpers
    def send_json(self, code, obj, headers=None):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        headers = dict(headers or {})
        if getattr(self, "_renew", False) and "Set-Cookie" not in headers:
            headers["Set-Cookie"] = self.session_cookie(getattr(self, "_sid", None))
            self._renew = False
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n < 0 or n > 65536:
            raise ValueError("body too large")
        raw = self.rfile.read(n) if n else b"{}"
        obj = json.loads(raw or b"{}")
        if not isinstance(obj, dict):
            raise ValueError("请求格式错误")
        return obj

    def session(self):
        try:
            c = SimpleCookie(self.headers.get("Cookie", ""))
        except Exception:
            return None
        return parse_session(c["vt_session"].value) if "vt_session" in c else None

    def authed(self):
        s = self.session()
        if not s:
            return False
        self._sid = s[1]
        # 滑动续期：签发超过一天就换一张新的（会话ID不变），长期有访问就一直保持登录
        if s[0] - time.time() < SESSION_TTL - 86400:
            self._renew = True
        return True

    def from_proxy(self):
        v = self.client_address[0]
        v = v[7:] if v.startswith("::ffff:") else v
        try:
            a = ipaddress.ip_address(v)
        except ValueError:
            return False
        return any(a in n for n in TRUSTED_PROXIES)

    def forwarded_https(self):
        return self.from_proxy() and self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def client_ip(self):
        """真实客户端 IP：只有直连对方是信任的反代时，才读取它转发的头"""
        def norm(v):
            v = v.strip()
            return v[7:] if v.startswith("::ffff:") else v

        def trusted(v):
            try:
                a = ipaddress.ip_address(v)
            except ValueError:
                return False
            return any(a in n for n in TRUSTED_PROXIES)

        ip = norm(self.client_address[0])
        if not self.from_proxy():
            return ip
        # 从右往左跳过信任的反代，第一个不信任的就是客户端
        for hop in reversed([norm(x) for x in self.headers.get("X-Forwarded-For", "").split(",") if x.strip()]):
            if not trusted(hop):
                return hop
        real = norm(self.headers.get("X-Real-IP", ""))
        return real if real else ip

    def session_cookie(self, sid=None):
        secure = "; Secure" if REQUIRE_HTTPS or self.forwarded_https() else ""
        return f"vt_session={make_session(sid)}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}{secure}"

    def base_url(self):
        if PUBLIC_URL:
            return PUBLIC_URL
        proto = "https" if REQUIRE_HTTPS or self.forwarded_https() else "http"
        host = self.headers.get("Host") or ""
        if not HOST_RE.match(host):                 # 只接受正常的主机名/IP[:端口]，防止拼进安装命令
            host = f"127.0.0.1:{PORT}"
        return f"{proto}://{host}"

    # ---- dispatch
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")

    def route(self, method):
        self._renew = False
        self._sid = None
        u = urllib.parse.urlparse(self.path)
        path, qs = u.path, urllib.parse.parse_qs(u.query)
        try:
            why = self.transport_ok()
            if why:
                return self.reject_transport(path, why)
            if method == "GET" and path in STATIC:
                return self.serve_static(*STATIC[path])
            m = FLAG_RE.match(path)
            if method == "GET" and m:
                return self.serve_static(f"flags/{m.group(1)}.png", "image/png", cache=True)
            if method == "GET" and path == "/api/site":
                return self.send_json(200, {"name": get_site_name(), "theme": get_theme()})
            if method == "POST" and path == "/api/report":
                ip = self.client_ip()
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else ""
                code, obj = handle_report(token, self.read_json(), ip)
                return self.send_json(code, obj)
            # Agent 上报靠 Token 认证、不带 Cookie，不需要 CSRF 检查；其余改动请求都要
            if method != "GET" and not self.csrf_ok():
                return self.send_json(403, {"error": "请求来源无效，请刷新页面后重试"})
            if method == "POST" and path == "/api/login":
                ip = self.client_ip()
                left = login_locked(ip)
                if left:
                    return self.send_json(429, {"error": f"登录失败次数过多，请 {left // 60 + 1} 分钟后再试"})
                b = self.read_json()
                if check_password(str(b.get("password", ""))):
                    login_ok(ip)
                    return self.send_json(200, {"ok": True}, {"Set-Cookie": self.session_cookie()})
                login_failed(ip)
                time.sleep(1)
                return self.send_json(401, {"error": "密码错误"})
            if method == "POST" and path == "/api/logout":
                s = self.session()
                if s:
                    revoke_session(s[1])            # 这个会话（含被复制走的 Cookie）立即失效
                return self.send_json(200, {"ok": True}, {"Set-Cookie": "vt_session=; Path=/; Max-Age=0; SameSite=Strict"})
            if not path.startswith("/api/"):
                return self.send_json(404, {"error": "not found"})
            if not self.authed():
                return self.send_json(401, {"error": "未登录"})
            return self.api(method, path, qs)
        except ValueError as e:
            return self.send_json(400, {"error": str(e)})
        except Exception as e:
            print(f"[http] {method} {path}: {e!r}")
            return self.send_json(500, {"error": "internal error"})

    def send_backup(self):
        path = export_backup()
        try:
            size = os.path.getsize(path)
            name = f"vps-traffic-{datetime.now(TZ).strftime('%Y%m%d-%H%M')}.db"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with open(path, "rb") as f:
                shutil.copyfileobj(f, self.wfile, 1024 * 256)
        finally:
            os.remove(path)

    def receive_restore(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return self.send_json(400, {"error": "没有收到文件"})
        if n > MAX_RESTORE:
            return self.send_json(413, {"error": "文件超过 1 GiB 上限"})
        fd, path = tempfile.mkstemp(prefix="vt-restore-", suffix=".db", dir=os.path.dirname(DB_PATH) or ".")
        try:
            with os.fdopen(fd, "wb") as f:
                left = n
                while left > 0:
                    chunk = self.rfile.read(min(left, 1024 * 256))
                    if not chunk:
                        raise ValueError("上传中断，请重试")
                    f.write(chunk)
                    left -= len(chunk)
            try:
                stats = restore_backup(path)
            except sqlite3.DatabaseError as e:
                return self.send_json(400, {"error": f"无法读取备份文件：{e}"})
            print(f"[restore] 已还原：{stats}")
            return self.send_json(200, stats)
        finally:
            for p in (path, path + "-wal", path + "-shm", path + "-journal"):
                if os.path.exists(p):
                    os.remove(p)

    def serve_static(self, fname, ctype, cache=False):
        fp = os.path.join(BASE, fname)
        if not os.path.exists(fp):
            return self.send_json(404, {"error": f"{fname} missing"})
        with open(fp, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if cache:
            self.send_header("Cache-Control", "public, max-age=2592000")
        self.end_headers()
        self.wfile.write(data)

    def api(self, method, path, qs):
        global LAST_VIEW
        LAST_VIEW = time.time()          # 有人在用面板，Agent 切到实时间隔
        now = int(time.time())
        if path == "/api/backup" and method == "GET":
            return self.send_backup()
        if path == "/api/restore" and method == "POST":
            return self.receive_restore()
        if path == "/api/range" and method == "GET":
            start_d, end_d = parse_range(qs, now)
            with txn() as conn:
                items = range_totals(conn, start_d, end_d)
            return self.send_json(200, {"start": start_d.isoformat(), "end": end_d.isoformat(), "servers": items,
                                        "rx": sum(i["rx"] for i in items), "tx": sum(i["tx"] for i in items)})
        if path == "/api/password" and method == "POST":
            b = self.read_json()
            if not check_password(str(b.get("old", ""))):
                return self.send_json(400, {"error": "当前密码不正确"})
            new = str(b.get("new", ""))
            if len(new) < 8:
                return self.send_json(400, {"error": "新密码至少 8 位"})
            set_password(new)
            return self.send_json(200, {"ok": True}, {"Set-Cookie": self.session_cookie()})
        if path == "/api/meta" and method == "GET":
            return self.send_json(200, {"tz": TZ_NAME, "now": now, "base_url": self.base_url(),
                                        "telegram": bool(TG_TOKEN and TG_CHAT),
                                        "session_days": SESSION_TTL // 86400,
                                        "interval": REPORT_INTERVAL, "idle_interval": IDLE_INTERVAL,
                                        "site_name": get_site_name(), "agent": AGENT_PIN})
        if path == "/api/settings" and method == "POST":
            b = self.read_json()
            set_intervals(b.get("interval"), b.get("idle_interval"))
            if "site_name" in b:
                set_site_name(b["site_name"])
            if "theme" in b:
                if b["theme"] not in THEMES:
                    raise ValueError("主题无效")
                with txn() as conn:
                    set_setting(conn, "theme", b["theme"])
            return self.send_json(200, {"ok": True, "interval": REPORT_INTERVAL, "idle_interval": IDLE_INTERVAL,
                                        "site_name": get_site_name()})
        if path == "/api/order" and method == "POST":
            ids = self.read_json().get("ids")
            if (not isinstance(ids, list) or len(ids) > MAX_ORDER_IDS
                    or not all(type(i) is int and 0 < i < 2 ** 62 for i in ids)):
                raise ValueError("排序数据无效")
            with txn() as conn:
                for n, sid in enumerate(ids):
                    conn.execute("UPDATE servers SET sort=? WHERE id=?", (n, sid))
            return self.send_json(200, {"ok": True})
        if path == "/api/servers":
            if method == "GET":
                with txn() as conn:
                    rows = conn.execute("SELECT * FROM servers ORDER BY sort, id").fetchall()
                    return self.send_json(200, [server_summary(conn, r, now) for r in rows])
            if method == "POST":
                f = clean_server_input(self.read_json())
                f.setdefault("anchor", None)
                if f["reset_type"] == "interval" and not f["anchor"]:
                    f["anchor"] = datetime.fromtimestamp(now, TZ).date().isoformat()
                token = secrets.token_urlsafe(24)
                with txn() as conn:
                    cur = conn.execute(
                        "INSERT INTO servers(name,note,token,quota_gb,billing,reset_type,reset_day,interval_days,anchor,created_at)"
                        " VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (f["name"], f.get("note", ""), token, f["quota_gb"], f["billing"], f["reset_type"],
                         f["reset_day"], f["interval_days"], f["anchor"], now))
                    conn.execute("UPDATE servers SET country=?, sort=(SELECT COALESCE(MAX(sort),0)+1 FROM servers) WHERE id=?",
                                 (f.get("country", ""), cur.lastrowid))
                    srv = conn.execute("SELECT * FROM servers WHERE id=?", (cur.lastrowid,)).fetchone()
                    ensure_cycle(conn, srv, now)
                    return self.send_json(200, {"id": srv["id"], "token": token})
        m = ROUTE_SRV.match(path)
        if not m:
            return self.send_json(404, {"error": "not found"})
        sid, sub = int(m.group(1)), m.group(2)
        with txn() as conn:
            srv = conn.execute("SELECT * FROM servers WHERE id=?", (sid,)).fetchone()
            if srv is None:
                return self.send_json(404, {"error": "服务器不存在"})
            if sub is None and method == "GET":
                d = server_summary(conn, srv, now)
                d["token"] = srv["token"]
                return self.send_json(200, d)
            if sub is None and method == "PUT":
                f = clean_server_input(self.read_json(), partial=True)
                if f:
                    sets = ", ".join(f"{k}=?" for k in f)
                    conn.execute(f"UPDATE servers SET {sets} WHERE id=?", (*f.values(), sid))
                    apply_rule_change(conn, sid, now)
                return self.send_json(200, {"ok": True})
            if sub is None and method == "DELETE":
                conn.execute("DELETE FROM servers WHERE id=?", (sid,))
                return self.send_json(200, {"ok": True})
            if sub == "daily" and method == "GET":
                return self.send_json(200, daily_stats(conn, sid, *parse_range(qs, now)))
            if sub == "metrics" and method == "GET":
                return self.send_json(200, metrics_series(conn, sid, qs.get("range", ["live"])[0], now))
            if sub == "hourly" and method == "GET":
                day = qs.get("date", [datetime.fromtimestamp(now, TZ).date().isoformat()])[0]
                return self.send_json(200, hourly_stats(conn, sid, day))
            if sub == "cycles" and method == "GET":
                rows = conn.execute("SELECT * FROM cycles WHERE server_id=? ORDER BY start_ts DESC, id DESC",
                                    (sid,)).fetchall()
                return self.send_json(200, [{
                    "id": r["id"], "start": r["start_ts"], "end": r["end_ts"], "rx": r["rx"], "tx": r["tx"],
                    "used": billed(r["rx"], r["tx"], r["billing"]), "quota_gb": r["quota_gb"],
                    "billing": r["billing"], "closed": bool(r["closed"]), "closed_at": r["closed_at"],
                    "reason": r["closed_reason"]} for r in rows])
            if sub == "reset" and method == "POST":
                cyc = ensure_cycle(conn, srv, now)
                close_cycle(conn, cyc, "manual", now)
                conn.execute("UPDATE cycles SET end_ts=? WHERE id=?", (now, cyc["id"]))
                open_cycle(conn, srv, now)
                return self.send_json(200, {"ok": True})
            if sub == "token" and method == "POST":
                token = secrets.token_urlsafe(24)
                conn.execute("UPDATE servers SET token=? WHERE id=?", (token, sid))
                return self.send_json(200, {"token": token})
        return self.send_json(405, {"error": "method not allowed"})


class LimitedServer(ThreadingHTTPServer):
    """限制同时处理的连接数，超出的直接断开，防止大量连接耗尽线程和内存"""
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, *a, **kw):
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(*a, **kw)

    def verify_request(self, request, client_address):
        """强制 HTTPS 时，非信任反代的连接在读取任何数据前直接断开：
        公网直连端口的人既拿不到页面，也占不住连接名额"""
        if not REQUIRE_HTTPS:
            return True
        v = client_address[0]
        v = v[7:] if v.startswith("::ffff:") else v
        try:
            a = ipaddress.ip_address(v)
        except ValueError:
            return False
        return any(a in n for n in TRUSTED_PROXIES)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def main():
    init_db()
    if len(sys.argv) >= 2 and sys.argv[1] == "--set-password":
        pw = sys.argv[2] if len(sys.argv) >= 3 else ""
        if pw == "-":
            pw = sys.stdin.readline().rstrip("\r\n")
        if len(pw) < 8:
            sys.exit("用法：python3 server.py --set-password 新密码（至少 8 位；用 - 表示从标准输入读取）")
        set_password(pw)
        print("密码已更新，请重启服务：systemctl restart vps-traffic-panel")
        return
    threading.Thread(target=maintenance_loop, daemon=True).start()
    httpd = LimitedServer((LISTEN, PORT), Handler)
    print(f"[start] 面板运行于 http://{LISTEN}:{PORT}  时区 {TZ_NAME}")
    if REQUIRE_HTTPS:
        print(f"[start] 强制 HTTPS：只接受来自 {os.environ.get('VT_TRUSTED_PROXIES', '127.0.0.1,::1')} "
              f"的 HTTPS 反代请求" + (f"，访问地址 {PUBLIC_URL}" if PUBLIC_URL else ""))
        if PUBLIC_URL and not PUBLIC_URL.startswith("https://"):
            sys.exit("[error] 已强制 HTTPS，VT_PUBLIC_URL 必须是 https:// 开头")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
