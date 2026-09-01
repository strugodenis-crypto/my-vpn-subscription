import requests
import re
import base64
import ipaddress
import socket
import subprocess
import json
import time
import urllib.parse
import random

print("=" * 50)
print("CONFIG HUNTER v11.0: ФИНАЛЬНЫЙ ТЕСТ")
print("=" * 50)

BLACK_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt"
XRAY = r"xray\xray.exe"
TEST_URL = "http://cp.cloudflare.com/generate_204"

def download(url):
    try:
        r = requests.get(url, timeout=20)
        return r.text if r.status_code == 200 else ""
    except:
        return ""

def extract_links(text):
    links = []
    for proto in ["vless://", "vmess://", "trojan://", "hysteria2://"]:
        links.extend(re.findall(re.escape(proto) + r'[^\s"<>#]+', text))
    return links

def load_sources():
    with open("sources.txt", "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def parse_vless(link):
    m = re.search(r'vless://([^@]+)@([^:]+):(\d+)', link)
    if not m:
        return None
    uuid, host, port = m.group(1), m.group(2), int(m.group(3))
    params = {}
    if '?' in link:
        q = link.split('?')[1].split('#')[0]
        for pair in q.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                params[k] = urllib.parse.unquote(v)
    return uuid, host, port, params

def build_xray_config(link, local_port):
    uuid, host, port, params = parse_vless(link)
    if not uuid:
        return None

    stream_settings = {
        "network": params.get("type", "tcp"),
        "security": params.get("security", "none")
    }

    if stream_settings["security"] == "reality":
        stream_settings["realitySettings"] = {
            "serverName": params.get("sni", ""),
            "publicKey": params.get("pbk", ""),
            "shortId": params.get("sid", ""),
            "fingerprint": params.get("fp", "chrome")
        }
    elif stream_settings["security"] == "tls":
        stream_settings["tlsSettings"] = {
            "serverName": params.get("sni", host)
        }

    if params.get("type") == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": params.get("serviceName", "")}

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": params.get("flow", "")
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    }
    return config

def test_connection(config, port):
    proc = None
    try:
        with open("tmp_config.json", "w") as f:
            json.dump(config, f)

        proc = subprocess.Popen(
            [XRAY, "run", "-config", "tmp_config.json"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(3)

        if proc.poll() is not None:
            return False

        proxies = {
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}"
        }
        response = requests.get(TEST_URL, proxies=proxies, timeout=5)
        return response.status_code == 204

    except:
        return False
    finally:
        if proc:
            proc.kill()
            time.sleep(1)

print("Загружаю черный список...")
black_text = download(BLACK_URL)
black_ips = set(re.findall(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", black_text))
print(f"Черный список: {len(black_ips)} IP")

print("Загружаю конфиги...")
all_links = []
for src in load_sources():
    text = download(src)
    all_links.extend(extract_links(text))

all_links = list(set(all_links))
print(f"Уникальных ссылок: {len(all_links)}")

alive = []
checked = set()
for link in all_links:
    if not link.startswith("vless://"):
        continue

    uuid, host, port, params = parse_vless(link)
    if not host:
        continue

    try:
        ipaddress.ip_address(host)
        real_ip = host
    except:
        try:
            real_ip = socket.gethostbyname(host)
        except:
            continue

    if real_ip in black_ips:
        continue

    key = f"{real_ip}:{port}"
    if key in checked:
        continue
    checked.add(key)

    local_port = random.randint(20000, 30000)

    print(f"[ТЕСТ] {key}", end="")

    config = build_xray_config(link, local_port)
    if not config:
        print(" - Ошибка парсинга")
        continue

    start = time.time()
    if test_connection(config, local_port):
        elapsed = time.time() - start
        alive.append(link)
        print(f" - ЖИВОЙ ✓ ({elapsed:.1f} сек)")
    else:
        print(" - МЕРТВЫЙ ✗")

with open("alive.txt", "w") as f:
    for link in alive:
        f.write(link + "\n")

if alive:
    raw = "\n".join(alive).encode()
    encoded = base64.b64encode(raw).decode()
    with open("subscription.txt", "w") as f:
        f.write(encoded)

print(f"\nГОТОВО. Прошло проверку: {len(alive)}")