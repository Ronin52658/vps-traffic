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
  VT_CLOUDFLARE  域名开了 Cloudflare 代理（橙色云朵）时设为 1，面板才能拿到访客和 Agent 的真实 IP
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
import urllib.error
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
def _norm_host(h):
    """Host 比较前去掉 https 默认端口和末尾的点"""
    h = (h or "").strip().lower()
    if h.endswith(":443"):
        h = h[:-4]
    return h.rstrip(".")


PUBLIC_HOST = _norm_host(urllib.parse.urlparse(PUBLIC_URL).netloc) if PUBLIC_URL else ""
HSTS_MAX_AGE = 31536000         # 浏览器记住一年：之后自动只用 HTTPS 访问该域名
TG_TOKEN = os.environ.get("VT_TG_TOKEN", "")
TG_CHAT = os.environ.get("VT_TG_CHAT", "")

METRICS_KEEP_DAYS = 7           # 系统监控（CPU/内存等）分钟数据保留天数
LATENCY_KEEP_DAYS = 30          # 延迟监测分钟数据保留天数
LATENCY_INTERVALS = (30, 60, 120, 300)   # 可选的探测间隔（秒）
MAX_LATENCY_TASKS = 50
MAX_GROUPS = 50
MAX_LAT_ITEMS = 300             # 单次上报最多带多少条延迟结果
HOURLY_KEEP_DAYS = 400          # 小时明细保留天数；周期记录永久保留
OFFLINE_AFTER = 180             # 超过几秒没上报视为离线（可在“设置”里改，60–3600 秒）
DEFAULT_OFFLINE_AFTER = 180
OFFLINE_NOTIFY = True           # 离线 / 恢复上线时发 Telegram 通知（可在“设置”里关）
START_TIME = time.time()
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
RESTORABLE_SETTINGS = ("interval", "idle_interval", "site_name", "theme", "offline_notify", "offline_after")


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

# 域名开了 Cloudflare 代理（橙色云朵）时：请求经 Cloudflare → NPM → 面板，NPM 在 X-Forwarded-For 末尾追加的是
# Cloudflare 节点的 IP。开启 VT_CLOUDFLARE=1 后，取真实 IP 时把 Cloudflare 的地址也当作“中间一跳”跳过，
# 拿到的就是访客 / Agent 的真实 IP。这些地址只用于识别转发链，不会被当作可直连面板的反代。
# 地址段来自 https://www.cloudflare.com/ips-v4 和 ips-v6；Cloudflare 改了可用 VT_CLOUDFLARE_IPS 覆盖
CF_DEFAULT = ("173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,"
              "190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,"
              "104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,2400:cb00::/32,2606:4700::/32,2803:f800::/32,"
              "2405:b500::/32,2405:8100::/32,2a06:98c0::/29,2c0f:f248::/32")
CLOUDFLARE = os.environ.get("VT_CLOUDFLARE", "0").strip().lower() in ("1", "true", "yes", "on")
CF_NETS = _parse_proxies(os.environ.get("VT_CLOUDFLARE_IPS") or CF_DEFAULT) if CLOUDFLARE else []


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
CREATE TABLE IF NOT EXISTS server_groups(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  sort INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS group_members(
  group_id INTEGER NOT NULL REFERENCES server_groups(id) ON DELETE CASCADE,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  PRIMARY KEY(group_id, server_id)
);
CREATE TABLE IF NOT EXISTS latency_tasks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'icmp',
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 0,
  interval INTEGER NOT NULL DEFAULT 60,
  sort INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS latency_targets(
  task_id INTEGER NOT NULL REFERENCES latency_tasks(id) ON DELETE CASCADE,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  PRIMARY KEY(task_id, server_id)
);
CREATE TABLE IF NOT EXISTS latency_minute(
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  task_id INTEGER NOT NULL REFERENCES latency_tasks(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  sent INTEGER NOT NULL DEFAULT 0,
  lost INTEGER NOT NULL DEFAULT 0,
  rtt_sum REAL NOT NULL DEFAULT 0,
  rtt_n INTEGER NOT NULL DEFAULT 0,
  jitter_sum REAL NOT NULL DEFAULT 0,
  rtt_max REAL,
  err INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(server_id, task_id, ts)
);
"""

# 旧版数据库或旧备份缺的字段，启动和还原时自动补上
SERVER_COLUMNS = {
    "notify_offline": "INTEGER NOT NULL DEFAULT 1",
    "alive_state": "TEXT NOT NULL DEFAULT ''",
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
    global REPORT_INTERVAL, IDLE_INTERVAL, OFFLINE_AFTER, OFFLINE_NOTIFY
    with txn() as conn:
        REPORT_INTERVAL = _clamp(get_setting(conn, "interval"), DEFAULT_INTERVAL)
        IDLE_INTERVAL = _clamp(get_setting(conn, "idle_interval"), DEFAULT_IDLE)
        try:
            OFFLINE_AFTER = min(3600, max(60, int(get_setting(conn, "offline_after") or DEFAULT_OFFLINE_AFTER)))
        except ValueError:
            OFFLINE_AFTER = DEFAULT_OFFLINE_AFTER
        OFFLINE_NOTIFY = get_setting(conn, "offline_notify") != "0"


def offline_after():
    """实际使用的离线判定时间：至少是空闲上报间隔的两倍再加 30 秒，避免没人看面板时被误判离线"""
    return max(OFFLINE_AFTER, IDLE_INTERVAL * 2 + 30)


def set_notify(enabled=None, after=None):
    with txn() as conn:
        if enabled is not None:
            set_setting(conn, "offline_notify", "1" if enabled else "0")
        if after is not None:
            try:
                n = int(after)
            except (TypeError, ValueError):
                raise ValueError("离线判定时间须为整数")
            if not 60 <= n <= 3600:
                raise ValueError("离线判定时间须在 1–60 分钟")
            set_setting(conn, "offline_after", str(n))
    load_interval()


DEFAULT_SITE_NAME = "VPS 流量"


def get_site_name():
    with txn() as conn:
        return get_site_name_conn(conn)


def get_site_name_conn(conn):
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

def tg_send_now(text):
    """同步发送，失败抛异常（“发送测试消息”用）"""
    data = urllib.parse.urlencode({"chat_id": TG_CHAT, "text": text}).encode()
    try:
        urllib.request.urlopen(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", data, timeout=10).read()
    except urllib.error.HTTPError as e:
        try:
            desc = json.loads(e.read()).get("description", "")
        except Exception:
            desc = ""
        raise RuntimeError(f"Telegram 返回 {e.code} {desc}".strip())   # 不带 URL，免得 Bot Token 出现在日志里
    except Exception as e:
        raise RuntimeError(f"连不上 Telegram：{getattr(e, 'reason', e)}")


def tg_send(text):
    if not (TG_TOKEN and TG_CHAT):
        return

    def run():
        try:
            tg_send_now(text)
        except Exception as e:
            print(f"[tg] 发送失败：{e}")
    threading.Thread(target=run, daemon=True).start()


def fmt_dur(sec):
    sec = max(0, int(sec))
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    if d:
        return f"{d} 天 {h} 小时"
    if h:
        return f"{h} 小时 {m} 分钟"
    return f"{max(1, m)} 分钟"


def fmt_time(ts):
    return datetime.fromtimestamp(ts, TZ).strftime("%Y-%m-%d %H:%M:%S")


def alive_loop():
    """每 15 秒检查一次：在线的机器超过离线判定时间没上报，就标记离线并通知；恢复上线的也在这里发出。多台同时离线或恢复都合并成一条。
    面板刚启动的一段时间内不判定离线：面板停机期间所有机器都没法上报，重启后不应该误报"""
    while True:
        time.sleep(15)
        try:
            check_alive(int(time.time()))
        except Exception as e:
            print(f"[alive] {e}")


_RECOVERED = []                 # 恢复上线、等待合并发送的：[(名称, 离线秒数)]
_RECOVER_LOCK = threading.Lock()


def flush_recovered():
    with _RECOVER_LOCK:
        items = _RECOVERED[:]
        _RECOVERED.clear()
    if not items:
        return
    site = get_site_name()
    if len(items) == 1:
        tg_send(f"🟢 [{site}] {items[0][0]} 恢复上线\n离线时长：{fmt_dur(items[0][1])}")
    else:
        tg_send(f"🟢 [{site}] {len(items)} 台 VPS 恢复上线\n" + "\n".join(f"· {n}（离线 {fmt_dur(d)}）" for n, d in items))


def check_alive(now):
    flush_recovered()
    limit = offline_after()
    if now - START_TIME < limit + 15:
        return
    gone = []
    with txn() as conn:
        for r in conn.execute("SELECT id, name, last_seen, notify_offline FROM servers "
                              "WHERE alive_state='online' AND last_seen<?", (now - limit,)).fetchall():
            conn.execute("UPDATE servers SET alive_state='offline' WHERE id=?", (r["id"],))
            if r["notify_offline"]:
                gone.append(r)
    if gone and OFFLINE_NOTIFY:
        site = get_site_name()
        lines = [f"· {r['name']}（最后上报 {fmt_time(r['last_seen'])}，{fmt_dur(now - r['last_seen'])}前）" for r in gone]
        head = f"🔴 [{site}] {gone[0]['name']} 离线" if len(gone) == 1 else f"🔴 [{site}] {len(gone)} 台 VPS 离线"
        tg_send(head + "\n" + "\n".join(lines))


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
    if not TOKEN_RE.fullmatch(token or ""):
        return 401, {"error": "invalid token"}
    with txn() as conn:
        srv = conn.execute("SELECT * FROM servers WHERE token=?", (token,)).fetchone()
        if srv is None:
            return 401, {"error": "invalid token"}
        conn.execute("""INSERT INTO traffic_hourly(server_id,ts,rx,tx) VALUES(?,?,?,?)
                        ON CONFLICT(server_id,ts) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx""",
                     (srv["id"], hour, rx, tx))
        cyc = ensure_cycle(conn, srv, now)
        conn.execute("UPDATE cycles SET rx=rx+?, tx=tx+? WHERE id=?", (rx, tx, cyc["id"]))
        if srv["alive_state"] != "online":
            conn.execute("UPDATE servers SET alive_state='online' WHERE id=?", (srv["id"],))
            if srv["alive_state"] == "offline" and srv["notify_offline"] and OFFLINE_NOTIFY:
                with _RECOVER_LOCK:                 # 攒一下，几秒内一起恢复的合并成一条
                    _RECOVERED.append((srv["name"], now - srv["last_seen"]))
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
        record_latency(conn, srv["id"], body.get("lat"), now)
        probes = probes_for(conn, srv["id"])
    # Agent 按 interval 调整上报间隔，按 probes 更新延迟探测任务
    return 200, {"ok": True, "interval": current_interval(), "probes": probes}


# ---------------------------------------------------------------- 延迟监测
# 面板只把“探测目标”交给 Agent（类型、主机、端口、间隔），Agent 自己用 ping 或 TCP 连接测量。
# 目标主机严格校验：只能是 IP 或普通域名，不能以 - 开头（防止被当成 ping 的参数）。

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def valid_probe_host(h):
    if not isinstance(h, str) or not h:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(h))


def clean_latency_input(b):
    for k in ("name", "kind", "host", "port", "interval"):
        if isinstance(b.get(k), (dict, list)):
            raise ValueError(f"字段 {k} 格式错误")
    name = re.sub(r"[\x00-\x1f]", "", str(b.get("name") or "")).strip()[:40]
    host = str(b.get("host") or "").strip().strip("[]").lower()
    if not valid_probe_host(host):
        raise ValueError("目标须为 IP 或域名，例如 1.1.1.1、2606:4700::1111、example.com")
    kind = b.get("kind") or "icmp"
    if kind not in ("icmp", "tcp"):
        raise ValueError("测试方式无效")
    port = 0
    if kind == "tcp":
        try:
            port = int(b.get("port"))
        except (TypeError, ValueError):
            raise ValueError("TCP 测试需要端口（1–65535）")
        if not 1 <= port <= 65535:
            raise ValueError("端口须在 1–65535")
    try:
        interval = int(b.get("interval") or 60)
    except (TypeError, ValueError):
        raise ValueError("间隔无效")
    if interval not in LATENCY_INTERVALS:
        raise ValueError("间隔须为 " + "、".join(map(str, LATENCY_INTERVALS)) + " 秒之一")
    ids = b.get("servers", [])
    if not isinstance(ids, list) or not all(type(i) is int and 0 < i < 2 ** 62 for i in ids) or len(ids) > 10000:
        raise ValueError("服务器列表无效")
    return {"name": name or host, "kind": kind, "host": host, "port": port, "interval": interval}, sorted(set(ids))


# ---------------------------------------------------------------- 分组（一台服务器可以在多个分组里）

def clean_group_input(b):
    if isinstance(b.get("name"), (dict, list)):
        raise ValueError("分组名称格式错误")
    name = re.sub(r"[\x00-\x1f<>]", "", str(b.get("name") or "")).strip()
    if not 1 <= len(name) <= 20:
        raise ValueError("分组名称须为 1–20 个字符")
    ids = b.get("servers", [])
    if not isinstance(ids, list) or len(ids) > 10000 or not all(type(i) is int and 0 < i < 2 ** 62 for i in ids):
        raise ValueError("服务器列表无效")
    return name, sorted(set(ids))


def list_groups(conn):
    groups = [{"id": r[0], "name": r[1], "servers": []} for r in conn.execute("SELECT id, name FROM server_groups ORDER BY sort, id")]
    idx = {g["id"]: g for g in groups}
    for gid, sid in conn.execute("SELECT group_id, server_id FROM group_members ORDER BY server_id"):
        if gid in idx:
            idx[gid]["servers"].append(sid)
    return groups


def set_group_members(conn, gid, ids):
    conn.execute("DELETE FROM group_members WHERE group_id=?", (gid,))
    conn.executemany("INSERT OR IGNORE INTO group_members(group_id, server_id) SELECT ?, id FROM servers WHERE id=?",
                     [(gid, i) for i in ids])


def set_server_groups(conn, sid, ids):
    if not isinstance(ids, list) or len(ids) > MAX_GROUPS * 2 or not all(type(i) is int and 0 < i < 2 ** 62 for i in ids):
        raise ValueError("分组列表无效")
    conn.execute("DELETE FROM group_members WHERE server_id=?", (sid,))
    conn.executemany("INSERT OR IGNORE INTO group_members(group_id, server_id) SELECT id, ? FROM server_groups WHERE id=?",
                     [(sid, g) for g in set(ids)])


def latency_tasks(conn):
    tasks = [dict(r) for r in conn.execute("SELECT id, name, kind, host, port, interval FROM latency_tasks ORDER BY sort, id")]
    assign = collections.defaultdict(list)
    for r in conn.execute("SELECT task_id, server_id FROM latency_targets"):
        assign[r[0]].append(r[1])
    for t in tasks:
        t["servers"] = sorted(assign.get(t["id"], []))
    return tasks


def set_task_servers(conn, tid, ids):
    conn.execute("DELETE FROM latency_targets WHERE task_id=?", (tid,))
    conn.executemany("INSERT OR IGNORE INTO latency_targets(task_id, server_id) SELECT ?, id FROM servers WHERE id=?",
                     [(tid, i) for i in ids])


def probes_for(conn, sid):
    """下发给 Agent 的探测任务：id,类型,主机,端口,间隔;…（只含安全字符，Agent 不用解析 JSON）"""
    rows = conn.execute("""SELECT t.id, t.kind, t.host, t.port, t.interval FROM latency_tasks t
                           JOIN latency_targets g ON g.task_id=t.id WHERE g.server_id=? ORDER BY t.id""", (sid,)).fetchall()
    return ";".join(f"{r[0]},{r[1]},{r[2]},{r[3]},{r[4]}" for r in rows if valid_probe_host(r[2]))


def record_latency(conn, sid, items, now):
    """Agent 送来的结果：[[任务id, 发出, 收到, 平均ms, 抖动ms, 最大ms], …]；收到为 -1 表示探测出错"""
    if not isinstance(items, list):
        return
    allowed = {r[0] for r in conn.execute("SELECT task_id FROM latency_targets WHERE server_id=?", (sid,))}
    m = now - now % 60
    for it in items[:MAX_LAT_ITEMS]:
        if not isinstance(it, list) or len(it) < 6:
            continue
        tid = it[0]
        if type(tid) is not int or tid not in allowed:
            continue
        sent, recv = _num(it[1], 0, 1000), _num(it[2], -1, 1000)
        avg, jit, mx = _num(it[3], 0, 60000), _num(it[4], 0, 60000), _num(it[5], 0, 60000)
        if sent is None or recv is None:
            continue
        sent, recv = int(sent), int(recv)
        err = 1 if recv < 0 else 0
        recv = max(0, min(recv, sent))
        ok = recv > 0 and avg is not None
        conn.execute("""INSERT INTO latency_minute(server_id, task_id, ts, sent, lost, rtt_sum, rtt_n, jitter_sum, rtt_max, err)
                        VALUES(?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(server_id, task_id, ts) DO UPDATE SET sent=sent+excluded.sent, lost=lost+excluded.lost,
                          rtt_sum=rtt_sum+excluded.rtt_sum, rtt_n=rtt_n+excluded.rtt_n, jitter_sum=jitter_sum+excluded.jitter_sum,
                          rtt_max=MAX(COALESCE(rtt_max, 0), COALESCE(excluded.rtt_max, 0)), err=err+excluded.err""",
                     (sid, tid, m, 0 if err else sent, 0 if err else sent - recv, avg if ok else 0, 1 if ok else 0,
                      (jit or 0) if ok else 0, (mx or avg) if ok else None, err))


LAT_RANGES = {"1h": 3600, "6h": 6 * 3600, "12h": 12 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}


def latency_series(conn, sid, qs, now):
    """按区间分桶（最多约 300 个点）：每个任务的平均延迟、丢包率、抖动、峰值"""
    rng = qs.get("range", ["1h"])[0]
    if rng == "custom":
        try:
            start, end = int(qs["start"][0]), int(qs["end"][0])
        except (KeyError, ValueError):
            raise ValueError("自定义区间无效")
        start = max(start, now - LATENCY_KEEP_DAYS * 86400)
        end = min(end, now)
        if end - start < 300:
            raise ValueError("自定义区间至少 5 分钟")
    else:
        end = now
        start = now - LAT_RANGES.get(rng, 3600)
    bucket = max(60, -(-(end - start) // 300) // 60 * 60)
    tasks = [dict(r) for r in conn.execute("""SELECT t.id, t.name, t.kind, t.host, t.port, t.interval FROM latency_tasks t
                                              JOIN latency_targets g ON g.task_id=t.id WHERE g.server_id=? ORDER BY t.sort, t.id""", (sid,))]
    rows = conn.execute(f"""SELECT task_id, (ts / {bucket}) * {bucket} AS b, SUM(sent) s, SUM(lost) l, SUM(rtt_sum) rs,
                                   SUM(rtt_n) rn, SUM(jitter_sum) js, MAX(rtt_max) mx, SUM(err) e
                            FROM latency_minute WHERE server_id=? AND ts>=? AND ts<=? GROUP BY task_id, b ORDER BY b""",
                        (sid, start, end)).fetchall()
    series = collections.defaultdict(list)
    tot = collections.defaultdict(lambda: [0, 0, 0.0, 0, 0.0, 0])
    for r in rows:
        avg = r["rs"] / r["rn"] if r["rn"] else None
        loss = r["l"] / r["s"] * 100 if r["s"] else None
        jit = r["js"] / r["rn"] if r["rn"] else None
        series[r["task_id"]].append([r["b"], avg, loss, jit, r["mx"] if r["rn"] else None, 1 if r["e"] and not r["s"] else 0])
        t = tot[r["task_id"]]
        t[0] += r["s"]; t[1] += r["l"]; t[2] += r["rs"]; t[3] += r["rn"]; t[4] += r["js"]; t[5] += r["e"]
    for t in tasks:
        pts, s = series.get(t["id"], []), tot.get(t["id"])
        # “当前”取最后一个时间桶：最近一次全部丢包时显示超时，而不是沿用更早的延迟
        t["points"] = pts
        t["stats"] = {"last": pts[-1][1] if pts else None,
                      "last_loss": pts[-1][2] if pts else None,
                      "avg": s[2] / s[3] if s and s[3] else None,
                      "loss": s[1] / s[0] * 100 if s and s[0] else None,
                      "jitter": s[4] / s[3] if s and s[3] else None,
                      "error": bool(s and s[5] and not s[0])}
    return {"start": start, "end": end, "bucket": bucket, "tasks": tasks}


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
    online = now - srv["last_seen"] <= offline_after()
    return {
        "id": srv["id"], "name": srv["name"], "note": srv["note"], "notify_offline": bool(srv["notify_offline"]),
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


def _parse_day(v):
    d = date.fromisoformat(v)
    if not 2000 <= d.year <= 2200:
        raise ValueError("日期超出范围")
    return d


def parse_range(qs, now):
    """start/end 为 YYYY-MM-DD（含首尾两天）；没给时用 days 往回推"""
    if qs.get("start") and qs.get("end"):
        start_d = _parse_day(qs["start"][0])
        end_d = _parse_day(qs["end"][0])
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
    d = _parse_day(day_str)
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


SERVER_FIELDS = ("name", "note", "quota_gb", "billing", "reset_type", "reset_day", "interval_days", "country", "anchor",
                 "notify_offline")


def clean_server_input(b, partial=False):
    out = {}
    for k in SERVER_FIELDS:                     # 字段只能是字符串、数字、布尔或 null，不能是数组/对象
        if isinstance(b.get(k), (dict, list)):
            raise ValueError(f"字段 {k} 格式错误")
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
    if "notify_offline" in b:
        out["notify_offline"] = 1 if b["notify_offline"] in (True, 1, "1", "on", "true") else 0
    if "anchor" in b:
        a = b.get("anchor") or None
        if a:
            a = _parse_day(str(a)).isoformat()
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


def prune_latency(now):
    """删除 30 天前的延迟数据：按（服务器, 任务）分别删，走主键索引，不用全表扫描（满载时有上千万行）"""
    cut = now - LATENCY_KEEP_DAYS * 86400
    with txn() as conn:
        # 所有（服务器, 任务）组合都清：取消勾选后留下的旧数据也会按时删掉
        pairs = conn.execute("SELECT s.id, t.id FROM servers s, latency_tasks t").fetchall()
    for sid, tid in pairs:
        with txn() as conn:                     # 每组单独提交，不长时间占着数据库锁
            conn.execute("DELETE FROM latency_minute WHERE server_id=? AND task_id=? AND ts<?", (sid, tid, cut))


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
                prune_latency(now)
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


TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")


def _int_in(v, lo, hi, default):
    return v if type(v) is int and lo <= v <= hi else default


def _iso_or_none(v):
    try:
        return date.fromisoformat(v).isoformat() if isinstance(v, str) and len(v) == 10 else None
    except ValueError:
        return None


def _ip_or_empty(v):
    try:
        return str(ipaddress.ip_address(v)) if isinstance(v, str) and v else ""
    except ValueError:
        return ""


def _json_clean(v, parser):
    try:
        d = parser(json.loads(v)) if isinstance(v, str) and v else None
    except (ValueError, TypeError):
        d = None
    return json.dumps(d, ensure_ascii=False) if d else ""


def normalize_restored(conn):
    """备份文件可能被人改过：还原后把每个字段都校验/修正一遍，
    防止异常类型让页面崩溃，或把 HTML 塞进页面（存储型 XSS）"""
    now = int(time.time())
    seen_tokens = set()
    for r in conn.execute("SELECT * FROM servers").fetchall():
        token = r["token"] if isinstance(r["token"], str) and TOKEN_RE.fullmatch(r["token"]) else ""
        if not token or token in seen_tokens:
            token = secrets.token_urlsafe(24)           # 格式不对或重复：换新的（该机需重装 Agent）
        seen_tokens.add(token)
        q = r["quota_gb"]
        q = float(q) if type(q) in (int, float) and 0 <= q <= MAX_QUOTA_GB else 0.0
        txt = lambda v, n: re.sub(r"[\x00-\x1f]", "", v)[:n] if isinstance(v, str) else ""
        num = lambda v: float(v) if type(v) in (int, float) and 0 <= v < 1e15 else 0.0
        cc = lambda v: v if isinstance(v, str) and re.fullmatch(r"[A-Z]{2}", v) else ""
        name = txt(r["name"], 64).strip() or f"server-{r['id']}"
        conn.execute("""UPDATE servers SET name=?, note=?, token=?, quota_gb=?, billing=?, reset_type=?, reset_day=?,
                          interval_days=?, anchor=?, sort=?, created_at=?, last_seen=?, rate_rx=?, rate_tx=?, iface=?,
                          hostname=?, metrics=?, sysinfo=?, public_ip=?, country=?, geo_ip=?, geo_country=? WHERE id=?""",
                     (name, txt(r["note"], 200), token, q,
                      r["billing"] if r["billing"] in VALID_BILLING else "sum",
                      r["reset_type"] if r["reset_type"] in VALID_RESET else "monthly",
                      _int_in(r["reset_day"], 1, 31, 1), _int_in(r["interval_days"], 1, 3650, 30),
                      _iso_or_none(r["anchor"]), _int_in(r["sort"], 0, 2 ** 62, 0),
                      _int_in(r["created_at"], 0, 2 ** 40, now), _int_in(r["last_seen"], 0, 2 ** 40, 0),
                      num(r["rate_rx"]), num(r["rate_tx"]), txt(r["iface"], 32), txt(r["hostname"], 64),
                      _json_clean(r["metrics"], parse_sys), _json_clean(r["sysinfo"], parse_info),
                      _ip_or_empty(r["public_ip"]), cc(r["country"]), _ip_or_empty(r["geo_ip"]), cc(r["geo_country"]),
                      r["id"]))
    # 离线通知：开关只能是 0/1；在线状态一律清空，等 Agent 重新上报，避免还原后误报离线/上线
    conn.execute("UPDATE servers SET notify_offline=CASE WHEN notify_offline=0 THEN 0 ELSE 1 END, alive_state=''")
    if get_setting(conn, "offline_notify") not in (None, "0", "1"):
        conn.execute("DELETE FROM settings WHERE k='offline_notify'")
    v = get_setting(conn, "offline_after")
    if v is not None and not (str(v).isdigit() and 60 <= int(v) <= 3600):
        conn.execute("DELETE FROM settings WHERE k='offline_after'")
    # 可恢复的普通设置：名称、主题、间隔都按正常修改时的规则校验，不合格就删掉用默认值
    name = get_setting(conn, "site_name")
    if name is not None:
        name = re.sub(r"[\x00-\x1f<>]", "", str(name)).strip()
        if 1 <= len(name) <= 40:
            set_setting(conn, "site_name", name)
        else:
            conn.execute("DELETE FROM settings WHERE k='site_name'")
    if get_setting(conn, "theme") not in (None,) + THEMES:
        conn.execute("DELETE FROM settings WHERE k='theme'")
    for k in ("interval", "idle_interval"):
        v = get_setting(conn, k)
        if v is not None and not (str(v).isdigit() and 1 <= int(v) <= 300):
            conn.execute("DELETE FROM settings WHERE k=?", (k,))
    # 周期：数值列必须是整数，计费方式/原因/告警等级必须是已知值
    conn.execute("""DELETE FROM cycles WHERE typeof(server_id)!='integer' OR server_id NOT IN (SELECT id FROM servers)
                      OR typeof(start_ts)!='integer' OR typeof(rx)!='integer' OR typeof(tx)!='integer' OR rx<0 OR tx<0
                      OR typeof(end_ts) NOT IN ('integer','null') OR typeof(closed_at) NOT IN ('integer','null')""")
    conn.execute("UPDATE cycles SET quota_gb=0 WHERE typeof(quota_gb) NOT IN ('integer','real') OR NOT (quota_gb BETWEEN 0 AND ?)",
                 (MAX_QUOTA_GB,))
    conn.execute("UPDATE cycles SET billing='sum' WHERE billing NOT IN ('sum','out','in','max')")
    conn.execute("UPDATE cycles SET closed=CASE WHEN closed=1 THEN 1 ELSE 0 END")
    conn.execute("UPDATE cycles SET closed_reason='manual' WHERE closed_reason IS NOT NULL AND closed_reason NOT IN ('auto','manual')")
    conn.execute("UPDATE cycles SET alert_level=0 WHERE alert_level NOT IN (0,80,95,100)")
    conn.execute("""DELETE FROM traffic_hourly WHERE typeof(server_id)!='integer' OR server_id NOT IN (SELECT id FROM servers)
                      OR typeof(ts)!='integer' OR typeof(rx)!='integer' OR typeof(tx)!='integer' OR rx<0 OR tx<0""")
    # 分组：名称按正常新增时的规则校验，成员只能指向存在的分组和服务器
    for r in conn.execute("SELECT id, name, sort FROM server_groups").fetchall():
        try:
            name, _ = clean_group_input({"name": r["name"]})
        except ValueError:
            conn.execute("DELETE FROM server_groups WHERE id=?", (r["id"],))
            continue
        conn.execute("UPDATE server_groups SET name=?, sort=? WHERE id=?", (name, _int_in(r["sort"], 0, 2 ** 62, 0), r["id"]))
    conn.execute("""DELETE FROM group_members WHERE typeof(group_id)!='integer' OR typeof(server_id)!='integer'
                      OR group_id NOT IN (SELECT id FROM server_groups) OR server_id NOT IN (SELECT id FROM servers)""")
    # 延迟监测：任务字段按正常新增时的规则校验，不合格的任务连同数据删除
    for r in conn.execute("SELECT * FROM latency_tasks").fetchall():
        try:
            f, _ = clean_latency_input({k: r[k] for k in ("name", "kind", "host", "port", "interval")})
        except (ValueError, TypeError):
            conn.execute("DELETE FROM latency_tasks WHERE id=?", (r["id"],))
            continue
        conn.execute("UPDATE latency_tasks SET name=?, kind=?, host=?, port=?, interval=?, sort=?, created_at=? WHERE id=?",
                     (f["name"], f["kind"], f["host"], f["port"], f["interval"], _int_in(r["sort"], 0, 2 ** 62, 0),
                      _int_in(r["created_at"], 0, 2 ** 40, 0), r["id"]))
    conn.execute("""DELETE FROM latency_targets WHERE typeof(task_id)!='integer' OR typeof(server_id)!='integer'
                      OR task_id NOT IN (SELECT id FROM latency_tasks) OR server_id NOT IN (SELECT id FROM servers)""")
    lat_bad = " OR ".join(f"typeof({c}) NOT IN ('integer','real')" for c in ("sent", "lost", "rtt_sum", "rtt_n", "jitter_sum", "err"))
    conn.execute(f"""DELETE FROM latency_minute WHERE typeof(server_id)!='integer' OR typeof(task_id)!='integer'
                      OR typeof(ts)!='integer' OR typeof(rtt_max) NOT IN ('integer','real','null') OR {lat_bad}
                      OR server_id NOT IN (SELECT id FROM servers) OR task_id NOT IN (SELECT id FROM latency_tasks)""")
    cols = ("cpu_sum", "load1", "mem_used", "mem_total", "swap_used", "swap_total", "disk_used", "disk_total",
            "tcp", "udp", "procs", "rx", "tx", "n")
    bad = " OR ".join(f"typeof({c}) NOT IN ('integer','real','null')" for c in cols)
    conn.execute(f"""DELETE FROM metrics_minute WHERE typeof(server_id)!='integer'
                      OR server_id NOT IN (SELECT id FROM servers) OR typeof(ts)!='integer' OR {bad}""")


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
            normalize_restored(live)            # 逐字段校验，被改过的备份也不能塞进异常数据或 HTML
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
# 网站图标：浏览器标签页、收藏夹、手机“添加到主屏幕”
ICONS = {"/favicon.svg": ("icons/favicon.svg", "image/svg+xml"),
         "/favicon.ico": ("icons/favicon.ico", "image/x-icon"),
         "/apple-touch-icon.png": ("icons/apple-touch-icon.png", "image/png"),
         "/icon-512.png": ("icons/icon-512.png", "image/png")}

ROUTE_SRV = re.compile(r"^/api/servers/(\d{1,15})(?:/(daily|hourly|cycles|reset|token|metrics|latency))?$")
ROUTE_GRP = re.compile(r"^/api/groups/(\d{1,15})$")
ROUTE_LAT = re.compile(r"^/api/latency/(\d{1,15})$")
ROUTE_LAT_SRV = re.compile(r"^/api/latency/server/(\d{1,15})$")


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
        # 页面不加载任何外部资源：脚本、样式、图片、请求都只许来自面板自己，
        # 即使将来出现注入，也无法加载外部脚本或把数据发到别的网站
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
                         "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def transport_ok(self):
        """强制 HTTPS 反代：返回拒绝原因，空字符串表示放行"""
        if REQUIRE_HTTPS and not self.forwarded_https():
            if not self.from_proxy():
                return "面板只能通过 HTTPS 反代访问，不能直接用 IP:端口 访问"
            return "反代没有使用 HTTPS（X-Forwarded-Proto 不是 https）"
        if PUBLIC_HOST and _norm_host(self.headers.get("Host")) != PUBLIC_HOST:
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
            return _norm_host(urllib.parse.urlparse(origin).netloc) == _norm_host(self.headers.get("Host"))
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
            return any(a in n for n in TRUSTED_PROXIES) or any(a in n for n in CF_NETS)

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
            if method == "GET" and path in ICONS:
                return self.serve_static(*ICONS[path], cache=True)
            if method == "GET" and path == "/manifest.webmanifest":
                return self.send_manifest()
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

    def notify_meta(self):
        return {"offline_notify": OFFLINE_NOTIFY, "offline_after": OFFLINE_AFTER, "offline_effective": offline_after()}

    def api_groups(self, method, path):
        """分组：首页按分组切换查看；一台服务器可以属于多个分组"""
        if path == "/api/groups" and method == "GET":
            with txn() as conn:
                return self.send_json(200, list_groups(conn))
        if path == "/api/groups" and method == "POST":
            name, ids = clean_group_input(self.read_json())
            with txn() as conn:
                if conn.execute("SELECT COUNT(*) FROM server_groups").fetchone()[0] >= MAX_GROUPS:
                    raise ValueError(f"最多 {MAX_GROUPS} 个分组")
                cur = conn.execute("INSERT INTO server_groups(name, sort) VALUES(?, (SELECT COALESCE(MAX(sort),0)+1 FROM server_groups))", (name,))
                set_group_members(conn, cur.lastrowid, ids)
                return self.send_json(200, {"id": cur.lastrowid})
        if path == "/api/groups/order" and method == "POST":
            ids = self.read_json().get("ids")
            if not isinstance(ids, list) or len(ids) > MAX_GROUPS * 2 or not all(type(i) is int and 0 < i < 2 ** 62 for i in ids):
                raise ValueError("排序数据无效")
            with txn() as conn:
                for n, gid in enumerate(ids):
                    conn.execute("UPDATE server_groups SET sort=? WHERE id=?", (n, gid))
            return self.send_json(200, {"ok": True})
        m = ROUTE_GRP.match(path)
        if m and method in ("PUT", "DELETE"):
            gid = int(m.group(1))
            with txn() as conn:
                if not conn.execute("SELECT 1 FROM server_groups WHERE id=?", (gid,)).fetchone():
                    return self.send_json(404, {"error": "分组不存在"})
                if method == "DELETE":
                    conn.execute("DELETE FROM server_groups WHERE id=?", (gid,))   # 只删分组，服务器不受影响
                    return self.send_json(200, {"ok": True})
                name, ids = clean_group_input(self.read_json())
                conn.execute("UPDATE server_groups SET name=? WHERE id=?", (name, gid))
                set_group_members(conn, gid, ids)
            return self.send_json(200, {"ok": True})
        return self.send_json(404, {"error": "not found"})

    def api_latency(self, method, path, now):
        """延迟监测任务管理：任务视图（每个目标选哪些服务器）和服务器视图（每台服务器测哪些目标）"""
        if path == "/api/latency" and method == "GET":
            with txn() as conn:
                return self.send_json(200, {"tasks": latency_tasks(conn), "intervals": LATENCY_INTERVALS})
        if path == "/api/latency" and method == "POST":
            f, ids = clean_latency_input(self.read_json())
            with txn() as conn:
                if conn.execute("SELECT COUNT(*) FROM latency_tasks").fetchone()[0] >= MAX_LATENCY_TASKS:
                    raise ValueError(f"最多 {MAX_LATENCY_TASKS} 个测试目标")
                cur = conn.execute("""INSERT INTO latency_tasks(name, kind, host, port, interval, sort, created_at)
                                      VALUES(?,?,?,?,?,(SELECT COALESCE(MAX(sort),0)+1 FROM latency_tasks),?)""",
                                   (f["name"], f["kind"], f["host"], f["port"], f["interval"], now))
                set_task_servers(conn, cur.lastrowid, ids)
                return self.send_json(200, {"id": cur.lastrowid})
        if path == "/api/latency/order" and method == "POST":
            ids = self.read_json().get("ids")
            if (not isinstance(ids, list) or len(ids) > MAX_LATENCY_TASKS * 2
                    or not all(type(i) is int and 0 < i < 2 ** 62 for i in ids)):
                raise ValueError("排序数据无效")
            with txn() as conn:
                for n, tid in enumerate(ids):
                    conn.execute("UPDATE latency_tasks SET sort=? WHERE id=?", (n, tid))
            return self.send_json(200, {"ok": True})
        m = ROUTE_LAT_SRV.match(path)
        if m and method == "PUT":
            sid = int(m.group(1))
            ids = self.read_json().get("tasks")
            if not isinstance(ids, list) or not all(type(i) is int and 0 < i < 2 ** 62 for i in ids):
                raise ValueError("任务列表无效")
            with txn() as conn:
                if not conn.execute("SELECT 1 FROM servers WHERE id=?", (sid,)).fetchone():
                    return self.send_json(404, {"error": "服务器不存在"})
                conn.execute("DELETE FROM latency_targets WHERE server_id=?", (sid,))
                conn.executemany("INSERT OR IGNORE INTO latency_targets(task_id, server_id) SELECT id, ? FROM latency_tasks WHERE id=?",
                                 [(sid, t) for t in set(ids)])
            return self.send_json(200, {"ok": True})
        m = ROUTE_LAT.match(path)
        if m and method in ("PUT", "DELETE"):
            tid = int(m.group(1))
            with txn() as conn:
                if not conn.execute("SELECT 1 FROM latency_tasks WHERE id=?", (tid,)).fetchone():
                    return self.send_json(404, {"error": "测试目标不存在"})
                if method == "DELETE":
                    conn.execute("DELETE FROM latency_tasks WHERE id=?", (tid,))   # 历史数据随之删除
                    return self.send_json(200, {"ok": True})
                f, ids = clean_latency_input(self.read_json())
                old = conn.execute("SELECT kind, host, port FROM latency_tasks WHERE id=?", (tid,)).fetchone()
                conn.execute("UPDATE latency_tasks SET name=?, kind=?, host=?, port=? , interval=? WHERE id=?",
                             (f["name"], f["kind"], f["host"], f["port"], f["interval"], tid))
                if (old["kind"], old["host"], old["port"]) != (f["kind"], f["host"], f["port"]):
                    conn.execute("DELETE FROM latency_minute WHERE task_id=?", (tid,))   # 换了目标，旧数据没有可比性
                set_task_servers(conn, tid, ids)
            return self.send_json(200, {"ok": True})
        return self.send_json(404, {"error": "not found"})

    def send_manifest(self):
        """添加到主屏幕用的应用清单，名称跟随面板“设置”里的名称"""
        name = get_site_name()
        data = json.dumps({
            "name": name, "short_name": name[:12], "start_url": "/", "display": "standalone",
            "background_color": "#E4E9F0", "theme_color": "#1F2A37",
            "icons": [{"src": "/favicon.svg", "sizes": "any", "type": "image/svg+xml"},
                      {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"}],
        }, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/manifest+json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

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
            ip = self.client_ip()
            left = login_locked(ip)
            if left:
                return self.send_json(429, {"error": f"尝试次数过多，请 {left // 60 + 1} 分钟后再试"})
            b = self.read_json()
            if not check_password(str(b.get("old", ""))):
                login_failed(ip)                    # 和登录共用限流，防止拿到会话的人暴力猜原密码
                time.sleep(1)
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
                                        "site_name": get_site_name(), "agent": AGENT_PIN, **self.notify_meta()})
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
            if "offline_notify" in b or "offline_after" in b:
                v = b.get("offline_notify")
                if "offline_notify" in b and v not in (True, False, 0, 1, "0", "1"):
                    raise ValueError("通知开关无效")
                set_notify(v in (True, 1, "1") if "offline_notify" in b else None, b.get("offline_after"))
            return self.send_json(200, {"ok": True, "interval": REPORT_INTERVAL, "idle_interval": IDLE_INTERVAL,
                                        "site_name": get_site_name(), **self.notify_meta()})
        if path == "/api/notify/test" and method == "POST":
            if not (TG_TOKEN and TG_CHAT):
                raise ValueError("还没有配置 Telegram：在面板机器的 /etc/vps-traffic-panel.env 里填 VT_TG_TOKEN 和 VT_TG_CHAT，再重启面板")
            try:
                tg_send_now(f"✅ [{get_site_name()}] 测试消息：Telegram 通知配置正常")
            except RuntimeError as e:
                raise ValueError(str(e))
            return self.send_json(200, {"ok": True})
        if path.startswith("/api/latency"):
            return self.api_latency(method, path, now)
        if path.startswith("/api/groups"):
            return self.api_groups(method, path)
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
                b = self.read_json()
                f = clean_server_input(b)
                if "groups" in b and not (isinstance(b["groups"], list) and all(type(i) is int and 0 < i < 2 ** 62 for i in b["groups"])):
                    raise ValueError("分组列表无效")
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
                    conn.execute("UPDATE servers SET country=?, notify_offline=?, sort=(SELECT COALESCE(MAX(sort),0)+1 FROM servers) WHERE id=?",
                                 (f.get("country", ""), f.get("notify_offline", 1), cur.lastrowid))
                    srv = conn.execute("SELECT * FROM servers WHERE id=?", (cur.lastrowid,)).fetchone()
                    ensure_cycle(conn, srv, now)
                    if b.get("groups"):
                        set_server_groups(conn, srv["id"], b["groups"])
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
                b = self.read_json()
                f = clean_server_input(b, partial=True)
                if f:
                    sets = ", ".join(f"{k}=?" for k in f)
                    conn.execute(f"UPDATE servers SET {sets} WHERE id=?", (*f.values(), sid))
                    apply_rule_change(conn, sid, now)
                if "groups" in b:
                    set_server_groups(conn, sid, b["groups"])
                return self.send_json(200, {"ok": True})
            if sub is None and method == "DELETE":
                conn.execute("DELETE FROM servers WHERE id=?", (sid,))
                return self.send_json(200, {"ok": True})
            if sub == "daily" and method == "GET":
                return self.send_json(200, daily_stats(conn, sid, *parse_range(qs, now)))
            if sub == "latency" and method == "GET":
                return self.send_json(200, latency_series(conn, sid, qs, now))
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
    threading.Thread(target=alive_loop, daemon=True).start()
    httpd = LimitedServer((LISTEN, PORT), Handler)
    print(f"[start] 面板运行于 http://{LISTEN}:{PORT}  时区 {TZ_NAME}")
    if REQUIRE_HTTPS:
        print(f"[start] 强制 HTTPS：只接受来自 {os.environ.get('VT_TRUSTED_PROXIES', '127.0.0.1,::1')} "
              f"的 HTTPS 反代请求" + (f"，访问地址 {PUBLIC_URL}" if PUBLIC_URL else ""))
        if CLOUDFLARE:
            print("[start] 已开启 Cloudflare：取真实 IP 时跳过 Cloudflare 节点地址")
        if PUBLIC_URL and not PUBLIC_URL.startswith("https://"):
            sys.exit("[error] 已强制 HTTPS，VT_PUBLIC_URL 必须是 https:// 开头")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
