import base64
import json
import os
import platform
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import zipfile
from pathlib import Path

import requests


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

SOURCES_FILE = BASE_DIR / "sources.txt"
ALIVE_FILE = BASE_DIR / "alive.txt"
SUBSCRIPTION_FILE = BASE_DIR / "subscription.txt"

BLACK_URL = (
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/"
    "main/BLACK_SS%2BAll_RUS.txt"
)

TEST_URL = "https://cp.cloudflare.com/generate_204"

XRAY_DIR = BASE_DIR / ".xray"

REQUEST_TIMEOUT = 15
XRAY_START_TIMEOUT = 10
TEST_TIMEOUT = 15

MAX_CONFIGS = 1500

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/120 Safari/537.36"
)


# ============================================================
# OUTPUT
# ============================================================

def log(text):
    print(text, flush=True)


def ok(text):
    print(f"[+] {text}", flush=True)


def warn(text):
    print(f"[!] {text}", flush=True)


# ============================================================
# FILES
# ============================================================

def read_text(path):
    if not path.exists():
        return ""

    return path.read_text(
        encoding="utf-8",
        errors="ignore"
    )


def write_text(path, text):
    path.write_text(
        text,
        encoding="utf-8"
    )


# ============================================================
# DOWNLOAD
# ============================================================

def download_text(url):
    log(f"[DOWNLOAD] {url}")

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        response.raise_for_status()

        text = response.text

        log(f"         {len(text):,} bytes")

        return text

    except Exception as exc:
        warn(f"Download error: {exc}")
        return ""


# ============================================================
# SOURCES
# ============================================================

def load_sources():
    result = []

    if SOURCES_FILE.exists():
        for line in read_text(
            SOURCES_FILE
        ).splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            if line not in result:
                result.append(line)

    if BLACK_URL not in result:
        result.insert(0, BLACK_URL)

    return result


# ============================================================
# CONFIG EXTRACTION
# ============================================================

def extract_links(text):
    if not text:
        return []

    pattern = re.compile(
        r"(?:"
        r"vless|vmess|trojan|hysteria2|hy2"
        r")://[^\s\"'<>]+",
        re.IGNORECASE
    )

    result = []

    for link in pattern.findall(text):
        link = link.strip()
        link = link.rstrip("),.;")

        if link not in result:
            result.append(link)

    return result


# ============================================================
# BLACKLIST
# ============================================================

def extract_black_ips(text):
    result = set()

    if not text:
        return result

    for ip in re.findall(
        r"(?<![\d.])"
        r"(?:\d{1,3}\.){3}\d{1,3}"
        r"(?![\d.])",
        text
    ):
        parts = ip.split(".")

        try:
            if all(
                0 <= int(x) <= 255
                for x in parts
            ):
                result.add(ip)
        except ValueError:
            pass

    return result


# ============================================================
# QUERY
# ============================================================

def query_dict(query):
    return urllib.parse.parse_qs(
        query,
        keep_blank_values=True
    )


def q(params, name, default=""):
    value = params.get(name)

    if not value:
        return default

    return value[0]


# ============================================================
# VLESS
# ============================================================

def parse_vless(url):
    try:
        parsed = urllib.parse.urlsplit(url)

        if parsed.scheme.lower() != "vless":
            return None

        if not parsed.username:
            return None

        uuid = urllib.parse.unquote(
            parsed.username
        )

        host = parsed.hostname

        if not host:
            return None

        port = parsed.port

        if not port:
            return None

        params = query_dict(
            parsed.query
        )

        return {
            "protocol": "vless",
            "uuid": uuid,
            "host": host,
            "port": port,
            "type": q(
                params,
                "type",
                "tcp"
            ).lower(),
            "security": q(
                params,
                "security",
                ""
            ).lower(),
            "sni": q(params, "sni", ""),
            "fp": q(params, "fp", ""),
            "pbk": q(params, "pbk", ""),
            "sid": q(params, "sid", ""),
            "spx": q(params, "spx", ""),
            "flow": q(params, "flow", ""),
            "path": q(params, "path", "/"),
            "host_header": q(params, "host", ""),
            "serviceName": q(
                params,
                "serviceName",
                ""
            ),
            "mode": q(
                params,
                "mode",
                ""
            ),
            "encryption": q(
                params,
                "encryption",
                "none"
            ),
            "alpn": q(
                params,
                "alpn",
                ""
            ),
            "name": urllib.parse.unquote(
                parsed.fragment
            ),
            "url": url,
        }

    except Exception:
        return None


# ============================================================
# VMESS
# ============================================================

def parse_vmess(url):
    try:
        raw = url[len("vmess://"):]

        raw = raw.split("#", 1)[0]

        raw += "=" * (
            (-len(raw)) % 4
        )

        decoded = base64.urlsafe_b64decode(
            raw
        ).decode(
            "utf-8",
            errors="ignore"
        )

        data = json.loads(decoded)

        host = (
            data.get("add")
            or data.get("host")
        )

        port = data.get("port")

        uuid = (
            data.get("id")
            or data.get("uuid")
        )

        if not host or not port or not uuid:
            return None

        try:
            port = int(port)
        except Exception:
            return None

        network = (
            data.get("net")
            or data.get("type")
            or "tcp"
        ).lower()

        security = (
            data.get("tls")
            or ""
        ).lower()

        if security in (
            "tls",
            "xtls"
        ):
            security = "tls"
        else:
            security = "none"

        return {
            "protocol": "vmess",
            "uuid": uuid,
            "host": host,
            "port": port,
            "type": network,
            "security": security,
            "sni": (
                data.get("sni")
                or data.get("host")
                or ""
            ),
            "fp": "",
            "pbk": "",
            "sid": "",
            "spx": "",
            "flow": "",
            "path": (
                data.get("path")
                or "/"
            ),
            "host_header": (
                data.get("host")
                or ""
            ),
            "serviceName": (
                data.get("path")
                or ""
            ),
            "mode": "",
            "encryption": "none",
            "alpn": "",
            "alterId": int(
                data.get("aid", 0)
                or 0
            ),
            "cipher": (
                data.get("scy")
                or "auto"
            ),
            "name": (
                data.get("ps")
                or ""
            ),
            "url": url,
        }

    except Exception:
        return None


# ============================================================
# TROJAN
# ============================================================

def parse_trojan(url):
    try:
        parsed = urllib.parse.urlsplit(url)

        if parsed.scheme.lower() != "trojan":
            return None

        password = urllib.parse.unquote(
            parsed.username or ""
        )

        host = parsed.hostname

        if not password or not host:
            return None

        port = parsed.port

        if not port:
            return None

        params = query_dict(
            parsed.query
        )

        return {
            "protocol": "trojan",
            "password": password,
            "host": host,
            "port": port,
            "type": q(
                params,
                "type",
                "tcp"
            ).lower(),
            "security": q(
                params,
                "security",
                "tls"
            ).lower(),
            "sni": q(
                params,
                "sni",
                ""
            ),
            "fp": q(
                params,
                "fp",
                ""
            ),
            "path": q(
                params,
                "path",
                "/"
            ),
            "host_header": q(
                params,
                "host",
                ""
            ),
            "serviceName": q(
                params,
                "serviceName",
                ""
            ),
            "alpn": q(
                params,
                "alpn",
                ""
            ),
            "name": urllib.parse.unquote(
                parsed.fragment
            ),
            "url": url,
        }

    except Exception:
        return None


# ============================================================
# HYSTERIA2
# ============================================================

def parse_hysteria2(url):
    try:
        parsed = urllib.parse.urlsplit(url)

        scheme = parsed.scheme.lower()

        if scheme not in (
            "hysteria2",
            "hy2"
        ):
            return None

        host = parsed.hostname

        if not host:
            return None

        port = parsed.port or 443

        password = urllib.parse.unquote(
            parsed.username or ""
        )

        params = query_dict(
            parsed.query
        )

        return {
            "protocol": "hysteria2",
            "password": password,
            "host": host,
            "port": port,
            "sni": q(
                params,
                "sni",
                ""
            ),
            "insecure": q(
                params,
                "insecure",
                "0"
            ),
            "obfs": q(
                params,
                "obfs",
                ""
            ),
            "obfs_password": q(
                params,
                "obfs-password",
                ""
            ),
            "name": urllib.parse.unquote(
                parsed.fragment
            ),
            "url": url,
        }

    except Exception:
        return None


# ============================================================
# PARSE ANY CONFIG
# ============================================================

def parse_config(url):
    scheme = urlsplit_scheme(url)

    if scheme == "vless":
        return parse_vless(url)

    if scheme == "vmess":
        return parse_vmess(url)

    if scheme == "trojan":
        return parse_trojan(url)

    if scheme in (
        "hysteria2",
        "hy2"
    ):
        return parse_hysteria2(url)

    return None


def urlsplit_scheme(url):
    try:
        return urllib.parse.urlsplit(
            url
        ).scheme.lower()
    except Exception:
        return ""


# ============================================================
# STREAM SETTINGS
# ============================================================

def build_stream_settings(config):
    protocol = config["protocol"]

    if protocol == "hysteria2":
        return None

    network = config.get(
        "type",
        "tcp"
    )

    security = config.get(
        "security",
        "none"
    )

    stream = {
        "network": network,
        "security": security,
    }

    if security == "tls":
        tls = {}

        if config.get("sni"):
            tls["serverName"] = config[
                "sni"
            ]

        if config.get("fp"):
            tls["fingerprint"] = config[
                "fp"
            ]

        if config.get("alpn"):
            tls["alpn"] = [
                x.strip()
                for x in config[
                    "alpn"
                ].split(",")
                if x.strip()
            ]

        stream["tlsSettings"] = tls

    elif security == "reality":
        reality = {
            "show": False
        }

        if config.get("sni"):
            reality["serverName"] = config[
                "sni"
            ]

        if config.get("fp"):
            reality["fingerprint"] = config[
                "fp"
            ]

        if config.get("pbk"):
            reality["publicKey"] = config[
                "pbk"
            ]

        if config.get("sid"):
            reality["shortId"] = config[
                "sid"
            ]

        if config.get("spx"):
            reality["spiderX"] = config[
                "spx"
            ]

        stream["realitySettings"] = reality

    if network == "ws":
        ws = {
            "path": config.get(
                "path",
                "/"
            )
        }

        host_header = config.get(
            "host_header"
        )

        if host_header:
            ws["headers"] = {
                "Host": host_header
            }

        stream["wsSettings"] = ws

    elif network == "grpc":
        grpc = {}

        service = config.get(
            "serviceName"
        )

        if service:
            grpc["serviceName"] = service

        stream["grpcSettings"] = grpc

    return stream


# ============================================================
# XRAY OUTBOUND
# ============================================================

def build_vless_outbound(config):
    user = {
        "id": config["uuid"],
        "encryption": config.get(
            "encryption",
            "none"
        )
    }

    if config.get("flow"):
        user["flow"] = config[
            "flow"
        ]

    return {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": config["host"],
                    "port": config["port"],
                    "users": [user],
                }
            ]
        },
        "streamSettings": (
            build_stream_settings(
                config
            )
        ),
    }


def build_vmess_outbound(config):
    user = {
        "id": config["uuid"],
        "alterId": config.get(
            "alterId",
            0
        ),
        "security": config.get(
            "cipher",
            "auto"
        ),
    }

    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": config["host"],
                    "port": config["port"],
                    "users": [user],
                }
            ]
        },
        "streamSettings": (
            build_stream_settings(
                config
            )
        ),
    }


def build_trojan_outbound(config):
    return {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": config["host"],
                    "port": config["port"],
                    "password": config[
                        "password"
                    ],
                }
            ]
        },
        "streamSettings": (
            build_stream_settings(
                config
            )
        ),
    }


def build_hysteria2_outbound(config):
    server = {
        "address": config["host"],
        "port": config["port"],
        "password": config.get(
            "password",
            ""
        ),
    }

    if config.get("sni"):
        server["sni"] = config[
            "sni"
        ]

    if str(
        config.get(
            "insecure",
            "0"
        )
    ).lower() in (
        "1",
        "true",
        "yes"
    ):
        server["skipCertVerify"] = True

    if config.get("obfs"):
        server["obfs"] = config[
            "obfs"
        ]

    if config.get("obfs_password"):
        server["obfs-password"] = config[
            "obfs_password"
        ]

    return {
        "protocol": "hysteria2",
        "settings": {
            "servers": [server]
        }
    }


def build_outbound(config):
    protocol = config[
        "protocol"
    ]

    if protocol == "vless":
        return build_vless_outbound(
            config
        )

    if protocol == "vmess":
        return build_vmess_outbound(
            config
        )

    if protocol == "trojan":
        return build_trojan_outbound(
            config
        )

    if protocol == "hysteria2":
        return build_hysteria2_outbound(
            config
        )

    return None


# ============================================================
# XRAY CONFIG
# ============================================================

def build_xray_config(
    config,
    socks_port
):
    outbound = build_outbound(
        config
    )

    if outbound is None:
        return None

    return {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                }
            }
        ],
        "outbounds": [
            outbound,
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ]
    }


# ============================================================
# XRAY FIND / DOWNLOAD
# ============================================================

def find_local_xray():
    candidates = []

    if platform.system().lower() == "windows":
        candidates.extend([
            BASE_DIR / "xray.exe",
            BASE_DIR / "xray" / "xray.exe",
            XRAY_DIR / "xray.exe",
        ])
    else:
        candidates.extend([
            BASE_DIR / "xray",
            BASE_DIR / "xray" / "xray",
            XRAY_DIR / "xray",
        ])

    for path in candidates:
        if path.exists():
            return path

    system_xray = shutil.which(
        "xray"
    )

    if system_xray:
        return Path(
            system_xray
        )

    return None


def download_xray_linux():
    XRAY_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    executable = (
        XRAY_DIR / "xray"
    )

    if executable.exists():
        try:
            executable.chmod(0o755)
        except Exception:
            pass

        return executable

    api = (
        "https://api.github.com/repos/"
        "XTLS/Xray-core/releases/latest"
    )

    log(
        "[XRAY] Downloading official Xray-core..."
    )

    try:
        response = requests.get(
            api,
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/vnd.github+json"
            }
        )

        response.raise_for_status()

        data = response.json()

    except Exception as exc:
        warn(
            f"Xray release lookup failed: {exc}"
        )
        return None

    selected = None

    for asset in data.get(
        "assets",
        []
    ):
        name = asset.get(
            "name",
            ""
        )

        if name.lower() == (
            "xray-linux-64.zip"
        ).lower():
            selected = asset
            break

    if selected is None:
        for asset in data.get(
            "assets",
            []
        ):
            name = asset.get(
                "name",
                ""
            ).lower()

            if (
                "linux-64" in name
                and name.endswith(".zip")
            ):
                selected = asset
                break

    if selected is None:
        warn(
            "Linux Xray asset not found"
        )
        return None

    url = selected.get(
        "browser_download_url"
    )

    if not url:
        return None

    archive = (
        XRAY_DIR / "xray.zip"
    )

    try:
        response = requests.get(
            url,
            timeout=60,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        response.raise_for_status()

        archive.write_bytes(
            response.content
        )

        with zipfile.ZipFile(
            archive,
            "r"
        ) as z:
            member = None

            for name in z.namelist():
                if (
                    name == "xray"
                    or name.endswith("/xray")
                ):
                    member = name
                    break

            if member is None:
                raise RuntimeError(
                    "xray executable missing"
                )

            with z.open(member) as src:
                executable.write_bytes(
                    src.read()
                )

        executable.chmod(
            0o755
        )

        archive.unlink(
            missing_ok=True
        )

        ok(
            f"Xray installed: {executable}"
        )

        return executable

    except Exception as exc:
        warn(
            f"Xray installation failed: {exc}"
        )
        return None


def get_xray():
    local = find_local_xray()

    if local:
        ok(
            f"Using Xray: {local}"
        )
        return local

    if platform.system().lower() == "linux":
        return download_xray_linux()

    warn(
        "Xray executable not found"
    )

    return None


# ============================================================
# XRAY PROCESS
# ============================================================

def validate_xray_config(
    xray,
    config_path
):
    try:
        process = subprocess.run(
            [
                str(xray),
                "run",
                "-test",
                "-config",
                str(config_path)
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        output = (
            process.stdout or ""
        ) + (
            process.stderr or ""
        )

        if process.returncode != 0:
            warn(
                "Xray configuration rejected:"
            )
            print(
                output[-5000:],
                flush=True
            )
            return False

        return True

    except Exception as exc:
        warn(
            f"Xray validation error: {exc}"
        )
        return False


def wait_for_port(
    port,
    timeout=XRAY_START_TIMEOUT
):
    deadline = (
        time.time()
        + timeout
    )

    while time.time() < deadline:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.5)

        try:
            if sock.connect_ex(
                (
                    "127.0.0.1",
                    port
                )
            ) == 0:
                return True

        except Exception:
            pass

        finally:
            sock.close()

        time.sleep(0.15)

    return False


def start_xray(
    xray,
    config_path,
    socks_port
):
    try:
        process = subprocess.Popen(
            [
                str(xray),
                "run",
                "-config",
                str(config_path)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        if wait_for_port(
            socks_port
        ):
            return process

        output = ""

        try:
            output = process.stdout.read(
                5000
            )
        except Exception:
            pass

        warn(
            "Xray did not open SOCKS port."
        )

        if output:
            print(
                output,
                flush=True
            )

        try:
            process.kill()
        except Exception:
            pass

        return None

    except Exception as exc:
        warn(
            f"Cannot start Xray: {exc}"
        )
        return None


def stop_xray(process):
    if not process:
        return

    try:
        process.terminate()

        try:
            process.wait(
                timeout=3
            )
        except subprocess.TimeoutExpired:
            process.kill()

    except Exception:
        pass


# ============================================================
# SOCKS5
# ============================================================

def socks5_connect(
    proxy_host,
    proxy_port,
    target_host,
    target_port,
    timeout=TEST_TIMEOUT
):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(
        timeout
    )

    sock.connect(
        (
            proxy_host,
            proxy_port
        )
    )

    sock.sendall(
        b"\x05\x01\x00"
    )

    greeting = sock.recv(
        2
    )

    if len(greeting) != 2:
        sock.close()
        raise OSError(
            "Invalid SOCKS5 greeting"
        )

    if greeting[0] != 5:
        sock.close()
        raise OSError(
            "Not SOCKS5"
        )

    if greeting[1] != 0:
        sock.close()
        raise OSError(
            "SOCKS5 authentication rejected"
        )

    host_bytes = target_host.encode(
        "idna"
    )

    if len(host_bytes) > 255:
        sock.close()
        raise OSError(
            "Hostname too long"
        )

    request = (
        b"\x05\x01\x00\x03"
        + bytes([len(host_bytes)])
        + host_bytes
        + int(target_port).to_bytes(
            2,
            "big"
        )
    )

    sock.sendall(
        request
    )

    response = sock.recv(
        4
    )

    if len(response) != 4:
        sock.close()
        raise OSError(
            "Invalid SOCKS5 response"
        )

    version, reply, _, address_type = response

    if version != 5:
        sock.close()
        raise OSError(
            "Invalid SOCKS5 version"
        )

    if reply != 0:
        sock.close()
        raise OSError(
            f"SOCKS5 reply {reply}"
        )

    if address_type == 1:
        remaining = 4

    elif address_type == 3:
        length_data = sock.recv(
            1
        )

        if len(length_data) != 1:
            sock.close()
            raise OSError(
                "Invalid domain response"
            )

        remaining = length_data[0]

    elif address_type == 4:
        remaining = 16

    else:
        sock.close()
        raise OSError(
            "Unknown address type"
        )

    while remaining > 0:
        chunk = sock.recv(
            remaining
        )

        if not chunk:
            sock.close()
            raise OSError(
                "Unexpected SOCKS5 EOF"
            )

        remaining -= len(chunk)

    port_data = sock.recv(
        2
    )

    if len(port_data) != 2:
        sock.close()
        raise OSError(
            "Invalid SOCKS5 port"
        )

    return sock


# ============================================================
# HTTPS THROUGH SOCKS5
# ============================================================

def socks_http_test(
    socks_port
):
    parsed = urllib.parse.urlsplit(
        TEST_URL
    )

    host = parsed.hostname

    port = parsed.port or 443

    path = parsed.path or "/"

    if parsed.query:
        path += "?" + parsed.query

    sock = socks5_connect(
        "127.0.0.1",
        socks_port,
        host,
        port
    )

    try:
        context = ssl.create_default_context()

        tls = context.wrap_socket(
            sock,
            server_hostname=host
        )

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Config-Hunter\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode(
            "ascii"
        )

        tls.sendall(
            request
        )

        data = b""

        while len(data) < 4096:
            chunk = tls.recv(
                4096
            )

            if not chunk:
                break

            data += chunk

            if b"\r\n\r\n" in data:
                break

        tls.close()

        if not data:
            return False

        first_line = data.split(
            b"\r\n",
            1
        )[0]

        match = re.search(
            rb"HTTP/\d(?:\.\d)?\s+(\d{3})",
            first_line
        )

        if not match:
            return False

        status = int(
            match.group(1)
        )

        return 200 <= status < 400

    except Exception:
        try:
            sock.close()
        except Exception:
            pass

        raise


# ============================================================
# DNS
# ============================================================

def resolve_ipv4(host):
    try:
        socket.inet_aton(
            host
        )
        return host

    except OSError:
        pass

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        for info in infos:
            ip = info[4][0]

            if ip:
                return ip

    except Exception:
        pass

    return None


# ============================================================
# COUNTRY
# ============================================================

COUNTRY_CACHE = {}


def get_country(ip):
    if not ip:
        return "??"

    if ip in COUNTRY_CACHE:
        return COUNTRY_CACHE[ip]

    try:
        response = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=6,
            headers={
                "User-Agent": USER_AGENT
            }
        )

        data = response.json()

        code = (
            data.get(
                "country_code"
            )
            or "??"
        ).upper()

        COUNTRY_CACHE[ip] = code

        return code

    except Exception:
        COUNTRY_CACHE[ip] = "??"
        return "??"


def country_flag(code):
    if (
        not code
        or len(code) != 2
        or not code.isalpha()
    ):
        return "🏳️"

    return "".join(
        chr(
            127397 + ord(c)
        )
        for c in code.upper()
    )


# ============================================================
# NAME
# ============================================================

def display_name(
    config,
    ip,
    country
):
    name = (
        config.get("name")
        or ""
    ).strip()

    if not name:
        name = (
            f"{config['host']}:"
            f"{config['port']}"
        )

    protocol = config[
        "protocol"
    ].upper()

    return (
        f"{country_flag(country)} "
        f"{protocol} | {name} "
        f"[{ip}]"
    )


# ============================================================
# TEST CONFIG
# ============================================================

def test_config(
    xray,
    config,
    blacklist
):
    ip = resolve_ipv4(
        config["host"]
    )

    if not ip:
        return (
            False,
            None,
            "DNS failed"
        )

    if ip in blacklist:
        return (
            False,
            ip,
            "blacklisted"
        )

    socks_port = random.randint(
        20000,
        50000
    )

    xray_config = build_xray_config(
        config,
        socks_port
    )

    if xray_config is None:
        return (
            False,
            ip,
            "unsupported protocol"
        )

    with tempfile.TemporaryDirectory(
        prefix="config_hunter_"
    ) as temp:

        config_path = (
            Path(temp)
            / "config.json"
        )

        config_path.write_text(
            json.dumps(
                xray_config,
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )

        if not validate_xray_config(
            xray,
            config_path
        ):
            return (
                False,
                ip,
                "invalid xray config"
            )

        process = start_xray(
            xray,
            config_path,
            socks_port
        )

        if process is None:
            return (
                False,
                ip,
                "xray start failed"
            )

        try:
            if socks_http_test(
                socks_port
            ):
                return (
                    True,
                    ip,
                    "HTTP test OK"
                )

            return (
                False,
                ip,
                "HTTP test failed"
            )

        except Exception as exc:
            return (
                False,
                ip,
                f"{type(exc).__name__}: {exc}"
            )

        finally:
            stop_xray(
                process
            )


# ============================================================
# SUBSCRIPTION
# ============================================================

def make_subscription(
    configs
):
    raw = "\n".join(
        item["url"]
        for item in configs
    )

    return base64.b64encode(
        raw.encode("utf-8")
    ).decode("ascii")


# ============================================================
# MAIN
# ============================================================

def main():
    log("=" * 60)
    log("CONFIG HUNTER")
    log(
        "VLESS / VMess / Trojan / Hysteria2"
    )
    log("=" * 60)

    log(
        f"[OS] {platform.system()}"
    )

    log("")

    # --------------------------------------------------------
    # SOURCES
    # --------------------------------------------------------

    sources = load_sources()

    log(
        f"[SOURCES] {len(sources)} sources"
    )

    if not sources:
        warn(
            "No sources configured"
        )

        write_text(
            ALIVE_FILE,
            ""
        )

        write_text(
            SUBSCRIPTION_FILE,
            ""
        )

        return 1

    downloaded = []

    for source in sources:
        text = download_text(
            source
        )

        if text:
            downloaded.append(
                (
                    source,
                    text
                )
            )

    # --------------------------------------------------------
    # BLACKLIST
    # --------------------------------------------------------

    blacklist = set()

    for source, text in downloaded:
        if source == BLACK_URL:
            blacklist.update(
                extract_black_ips(
                    text
                )
            )

    log(
        f"[BLACKLIST] {len(blacklist)} IPs"
    )

    # --------------------------------------------------------
    # EXTRACT
    # --------------------------------------------------------

    links = []

    for source, text in downloaded:
        found = extract_links(
            text
        )

        log(
            f"[EXTRACT] {len(found)} configs from source"
        )

        links.extend(
            found
        )

    unique_links = []

    seen = set()

    for link in links:
        if link in seen:
            continue

        seen.add(
            link
        )

        unique_links.append(
            link
        )

    log(
        f"[CONFIGS] Unique: {len(unique_links)}"
    )

    # --------------------------------------------------------
    # PARSE
    # --------------------------------------------------------

    configs = []

    counters = {
        "vless": 0,
        "vmess": 0,
        "trojan": 0,
        "hysteria2": 0,
    }

    failed_parse = 0

    for link in unique_links[:MAX_CONFIGS]:
        config = parse_config(
            link
        )

        if config is None:
            failed_parse += 1
            continue

        configs.append(
            config
        )

        protocol = config[
            "protocol"
        ]

        if protocol in counters:
            counters[
                protocol
            ] += 1

    log(
        f"[VLESS]      {counters['vless']}"
    )

    log(
        f"[VMESS]      {counters['vmess']}"
    )

    log(
        f"[TROJAN]     {counters['trojan']}"
    )

    log(
        f"[HYSTERIA2]  {counters['hysteria2']}"
    )

    if failed_parse:
        log(
            f"[PARSE] Failed: {failed_parse}"
        )

    # --------------------------------------------------------
    # XRAY
    # --------------------------------------------------------

    xray = get_xray()

    if xray is None:
        warn(
            "Xray unavailable"
        )

        write_text(
            ALIVE_FILE,
            ""
        )

        write_text(
            SUBSCRIPTION_FILE,
            ""
        )

        return 1

    # --------------------------------------------------------
    # TEST
    # --------------------------------------------------------

    alive = []

    total = len(
        configs
    )

    for index, config in enumerate(
        configs,
        1
    ):
        protocol = config[
            "protocol"
        ].upper()

        log("")

        log(
            f"[TEST {index}/{total}] "
            f"{protocol} "
            f"{config['host']}:"
            f"{config['port']}"
        )

        success, ip, reason = test_config(
            xray,
            config,
            blacklist
        )

        if success:
            country = get_country(
                ip
            )

            name = display_name(
                config,
                ip,
                country
            )

            alive.append(
                {
                    "url": config["url"],
                    "name": name,
                    "ip": ip,
                    "country": country,
                    "protocol": protocol,
                }
            )

            ok(
                f"LIVE {name}"
            )

        else:
            warn(
                f"DEAD {ip or config['host']} "
                f"— {reason}"
            )

    # --------------------------------------------------------
    # DEDUP
    # --------------------------------------------------------

    final_alive = []

    seen = set()

    for item in alive:
        if item["url"] in seen:
            continue

        seen.add(
            item["url"]
        )

        final_alive.append(
            item
        )

    # --------------------------------------------------------
    # ALIVE.TXT
    # --------------------------------------------------------

    alive_lines = []

    for item in final_alive:
        alive_lines.append(
            f"{item['name']} | "
            f"{item['url']}"
        )

    write_text(
        ALIVE_FILE,
        (
            "\n".join(
                alive_lines
            )
            + (
                "\n"
                if alive_lines
                else ""
            )
        )
    )

    # --------------------------------------------------------
    # SUBSCRIPTION.TXT
    # --------------------------------------------------------

    subscription = make_subscription(
        final_alive
    )

    write_text(
        SUBSCRIPTION_FILE,
        subscription
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    log("")
    log("=" * 60)
    log("RESULT")
    log("=" * 60)

    log(
        f"Sources:       {len(sources)}"
    )

    log(
        f"Blacklist IPs: {len(blacklist)}"
    )

    log(
        f"Unique configs:{len(unique_links)}"
    )

    log(
        f"VLESS:         {counters['vless']}"
    )

    log(
        f"VMess:         {counters['vmess']}"
    )

    log(
        f"Trojan:        {counters['trojan']}"
    )

    log(
        f"Hysteria2:     {counters['hysteria2']}"
    )

    log(
        f"Tested:        {total}"
    )

    log(
        f"ALIVE:         {len(final_alive)}"
    )

    log("")

    log(
        f"Saved: {ALIVE_FILE}"
    )

    log(
        f"Saved: {SUBSCRIPTION_FILE}"
    )

    log("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(
        main()
    )