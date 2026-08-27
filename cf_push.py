#!/usr/bin/env python3
"""
Cloudflare DNS 推送模块
- API Token 认证
- 创建/更新 A 记录
- 自动推送调度
"""
import json
import time
import threading
import urllib.request
import urllib.error

CF_API = "https://api.cloudflare.com/client/v4"

_cfg = {}       # 运行时配置
_lock = threading.Lock()
_scheduler = None


def _headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _api(token, method, path, body=None):
    url = f"{CF_API}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=_headers(token), method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", "replace")
        try:
            return json.loads(err_body)
        except Exception:
            return {"success": False, "errors": [{"message": f"HTTP {e.code}: {err_body[:200]}"}]}
    except Exception as e:
        return {"success": False, "errors": [{"message": str(e)}]}


def load_cf_settings(path):
    try:
        with open(path) as f:
            d = json.load(f)
        return {
            "token": d.get("cf_token", ""),
            "zone_id": d.get("cf_zone_id", ""),
            "domain": d.get("cf_domain", ""),
            "subdomain": d.get("cf_subdomain", "@"),
            "auto_enabled": d.get("cf_auto_enabled", False),
            "auto_interval": int(d.get("cf_auto_interval", 300)),
            "auto_min_bw": float(d.get("cf_auto_min_bw", 0)),
            "auto_max_lat": float(d.get("cf_auto_max_lat", 99999)),
            "auto_region": d.get("cf_auto_region", ""),
            "auto_ipv6": d.get("cf_auto_ipv6", "0"),
        }
    except Exception:
        return {}


def save_cf_settings(path, cfg):
    try:
        with open(path) as f:
            d = json.load(f)
    except Exception:
        d = {}
    d.update({
        "cf_token": cfg.get("token", ""),
        "cf_zone_id": cfg.get("zone_id", ""),
        "cf_domain": cfg.get("domain", ""),
        "cf_subdomain": cfg.get("subdomain", "@"),
        "cf_auto_enabled": cfg.get("auto_enabled", False),
        "cf_auto_interval": cfg.get("auto_interval", 300),
        "cf_auto_min_bw": cfg.get("auto_min_bw", 0),
        "cf_auto_max_lat": cfg.get("auto_max_lat", 99999),
        "cf_auto_region": cfg.get("auto_region", ""),
        "cf_auto_ipv6": cfg.get("cf_auto_ipv6", "0"),
    })
    with open(path, "w") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    with _lock:
        _cfg.update(cfg)


def test_connection(token, zone_id):
    try:
        r = _api(token, "GET", f"/zones/{zone_id}")
        if r.get("success"):
            z = r["result"]
            return {"ok": True, "name": z.get("name", "?"), "status": z.get("status", "?")}
        return {"ok": False, "error": r.get("errors", [{"message": "unknown"}])}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_dns_record(token, zone_id, domain, subdomain):
    name = f"{subdomain}.{domain}" if subdomain and subdomain != "@" else domain
    try:
        r = _api(token, "GET", f"/zones/{zone_id}/dns_records?name={name}&type=A")
        if r.get("success") and r.get("result"):
            rec = r["result"][0]
            return {"ok": True, "id": rec["id"], "ip": rec["content"],
                    "name": rec["name"], "ttl": rec.get("ttl", 1),
                    "proxied": rec.get("proxied", False)}
        r6 = _api(token, "GET", f"/zones/{zone_id}/dns_records?name={name}&type=AAAA")
        if r6.get("success") and r6.get("result"):
            rec = r6["result"][0]
            return {"ok": True, "id": rec["id"], "ip": rec["content"],
                    "name": rec["name"], "ttl": rec.get("ttl", 1),
                    "proxied": rec.get("proxied", False), "type": "AAAA"}
        return {"ok": False, "error": "记录不存在"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def push_ip(token, zone_id, domain, subdomain, ip, record_id=None, ttl=1, proxied=False):
    name = f"{subdomain}.{domain}" if subdomain and subdomain != "@" else domain
    is_v6 = ":" in ip
    rtype = "AAAA" if is_v6 else "A"
    body = {"type": rtype, "name": name, "content": ip, "ttl": ttl, "proxied": proxied}
    try:
        if record_id:
            r = _api(token, "PUT", f"/zones/{zone_id}/dns_records/{record_id}", body)
        else:
            existing = _api(token, "GET", f"/zones/{zone_id}/dns_records?name={name}&type={rtype}")
            if existing.get("success") and existing.get("result"):
                rid = existing["result"][0]["id"]
                r = _api(token, "PUT", f"/zones/{zone_id}/dns_records/{rid}", body)
            else:
                r = _api(token, "POST", f"/zones/{zone_id}/dns_records", body)
        if r.get("success"):
            rec = r["result"]
            return {"ok": True, "ip": rec["content"], "name": rec["name"],
                    "type": rec["type"], "ttl": rec.get("ttl"),
                    "proxied": rec.get("proxied")}
        return {"ok": False, "error": r.get("errors", [{"message": "unknown"}])}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def auto_push_once(cfg, db_path):
    import cf_db
    token = cfg.get("token", "")
    zone_id = cfg.get("zone_id", "")
    domain = cfg.get("domain", "")
    subdomain = cfg.get("subdomain", "@")
    if not all([token, zone_id, domain]):
        return {"ok": False, "error": "未配置 Cloudflare"}

    where_parts = ["ok_count > 0", "latency_ms IS NOT NULL"]
    params = []
    min_bw = cfg.get("auto_min_bw", 0)
    if min_bw > 0:
        where_parts.append("bw_last_mbps >= ?")
        params.append(min_bw)
    max_lat = cfg.get("auto_max_lat", 99999)
    if max_lat < 99999:
        where_parts.append("latency_ms <= ?")
        params.append(max_lat)
    region = cfg.get("auto_region", "").strip()
    if region:
        keep = [r.strip().upper() for r in region.split(",") if r.strip()]
        if keep:
            ph = ",".join("?" for _ in keep)
            where_parts.append(f"colo IN ({ph})")
            params.extend(keep)
            params.extend(keep)
    is_v6 = cfg.get("auto_ipv6", "0") == "1"
    if is_v6:
        where_parts.append("ip LIKE '%:%'")
    else:
        where_parts.append("ip NOT LIKE '%:%'")
    where = " AND ".join(where_parts)
    sql = (f"SELECT ip, port FROM ips WHERE {where} "
           f"ORDER BY bw_last_mbps DESC, latency_ms ASC LIMIT 1")
    conn = cf_db.open_db(db_path)
    try:
        row = conn.execute(sql, params).fetchone()
    finally:
        conn.close()
    if not row:
        return {"ok": False, "error": "无符合条件的 IP"}
    ip = row[0]
    existing = get_dns_record(token, zone_id, domain, subdomain)
    rec_id = existing.get("id") if existing.get("ok") else None
    return push_ip(token, zone_id, domain, subdomain, ip, record_id=rec_id)


class AutoPushScheduler:
    def __init__(self):
        self._running = False
        self._thread = None
        self._last_push = 0
        self._last_result = None

    @property
    def status(self):
        return {
            "running": self._running,
            "last_push": self._last_push,
            "last_result": self._last_result,
        }

    def start(self, cfg, settings_path, db_path, interval=300):
        self.stop()
        self._running = True
        def _loop():
            while self._running:
                try:
                    current = load_cf_settings(settings_path)
                    if not current.get("auto_enabled"):
                        time.sleep(10)
                        continue
                    interval_s = max(60, int(current.get("auto_interval", 300)))
                    if time.time() - self._last_push < interval_s:
                        time.sleep(min(10, interval_s))
                        continue
                    result = auto_push_once(current, db_path)
                    self._last_push = time.time()
                    self._last_result = result
                except Exception as e:
                    self._last_result = {"ok": False, "error": str(e)}
                time.sleep(5)
        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None


def get_scheduler():
    global _scheduler
    if _scheduler is None:
        _scheduler = AutoPushScheduler()
    return _scheduler
