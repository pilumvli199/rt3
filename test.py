#!/usr/bin/env python3
import os, socket, ssl, json, traceback, time
import redis
import certifi

REDIS_HOST = os.getenv("REDIS_HOST", "redis-14246.crce206.ap-south-1-1.ec2.redns.redis-cloud.com")
REDIS_PORT = int(os.getenv("REDIS_PORT", "14246"))
REDIS_USER = os.getenv("REDIS_USER", "default")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
REDIS_URL = os.getenv("REDIS_URL", "")

def print_hdr(txt): print("\n==== " + txt + " ====")

def try_plain():
    print_hdr("PLAIN (host/port) connection test")
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, username=REDIS_USER or None,
                        password=REDIS_PASSWORD or None, decode_responses=True, socket_connect_timeout=5)
        print("PING ->", r.ping())
        r.set("test_key_plain", f"ok:{int(time.time())}")
        print("GET ->", r.get("test_key_plain"))
    except Exception as e:
        print("Plain connection failed:", type(e), e)
        traceback.print_exc()

def try_from_url():
    print_hdr("redis.from_url() test")
    if not REDIS_URL:
        print("REDIS_URL not set"); return
    try:
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=5)
        print("PING ->", r.ping())
        r.set("test_key_url", f"ok:{int(time.time())}")
        print("GET ->", r.get("test_key_url"))
    except Exception as e:
        print("from_url() failed:", type(e), e)
        traceback.print_exc()

def ssl_socket_handshake():
    print_hdr("Low-level SSL socket handshake")
    host, port = REDIS_HOST, REDIS_PORT
    try:
        ctx = ssl.create_default_context(cafile=certifi.where())
        raw = socket.create_connection((host, port), timeout=8)
        ss = ctx.wrap_socket(raw, server_hostname=host)
        print("TLS handshake ok. Cipher:", ss.cipher())
        print("Peer cert subject:", ss.getpeercert().get("subject"))
        ss.close()
    except Exception as e:
        print("SSL handshake failed:", type(e), e)
        traceback.print_exc()

if __name__ == "__main__":
    print_hdr("ENV")
    print(json.dumps({
        "REDIS_HOST": REDIS_HOST,
        "REDIS_PORT": REDIS_PORT,
        "REDIS_USER": REDIS_USER,
        "REDIS_PASSWORD": "SET" if REDIS_PASSWORD else "NOT SET",
        "REDIS_URL": "SET" if REDIS_URL else "NOT SET"
    }, indent=2))
    try_plain()
    try_from_url()
    ssl_socket_handshake()
    print("\nDone tests.")
