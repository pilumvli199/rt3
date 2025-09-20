#!/usr/bin/env python3
# updated test.py - Redis connectivity tester (plain, secure, SSL handshake)
# Usage: set env vars (see .env.example) and run `python test.py`

import os, socket, ssl, json, traceback, time, base64
import redis
import certifi

# ----- Read env -----
REDIS_HOST = os.getenv("REDIS_HOST", "").strip()
REDIS_PORT = int(os.getenv("REDIS_PORT", "0")) if os.getenv("REDIS_PORT") else 0
REDIS_USER = os.getenv("REDIS_USER", "").strip() or None
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "").strip() or None
REDIS_URL = os.getenv("REDIS_URL", "").strip()  # e.g. rediss://default:PASS@host:port

# Optional: custom CA as base64-encoded PEM (useful if provider has private CA)
REDIS_CA_B64 = os.getenv("REDIS_CA_B64", "").strip()

# Where to write provider CA if present
PROVIDER_CA_PATH = "/tmp/redis_provider_ca.pem"

def print_hdr(t):
    print("\n" + "="*6 + " " + t + " " + "="*6)

def write_provider_ca_if_present():
    """If REDIS_CA_B64 is set, decode and write to PROVIDER_CA_PATH and return path.
       Otherwise return certifi.where() fallback path."""
    if REDIS_CA_B64:
        try:
            raw = base64.b64decode(REDIS_CA_B64)
            with open(PROVIDER_CA_PATH, "wb") as f:
                f.write(raw)
            print("Wrote provider CA to", PROVIDER_CA_PATH)
            return PROVIDER_CA_PATH
        except Exception as e:
            print("Failed to write provider CA:", e)
            traceback.print_exc()
            return certifi.where()
    else:
        return certifi.where()

def try_plain():
    print_hdr("PLAIN (host/port) connection test")
    if not REDIS_HOST or not REDIS_PORT:
        print("SKIP: REDIS_HOST / REDIS_PORT not set")
        return
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                        username=REDIS_USER, password=REDIS_PASSWORD,
                        decode_responses=True, socket_connect_timeout=5)
        print("Attempting PING (plain)...")
        ok = r.ping()
        print("PING ->", ok)
        key = f"test_key_plain_{int(time.time())}"
        r.set(key, "ok_plain")
        print("GET ->", r.get(key))
    except Exception as e:
        print("Plain connection failed:", type(e), e)
        traceback.print_exc()

def try_from_url_secure(cafile):
    print_hdr("SECURE from_url()/SSLConnection test")
    if not REDIS_URL:
        print("SKIP: REDIS_URL not set")
        return
    # two tries: 1) redis.from_url default, 2) explicit SSLConnection with cafile
    try:
        print("Attempting redis.from_url(...) (may auto-detect rediss://)...")
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=5)
        print("PING ->", r.ping())
        k = f"test_key_fromurl_{int(time.time())}"
        r.set(k, "ok_fromurl")
        print("GET ->", r.get(k))
        return
    except Exception as e:
        print("from_url() failed (first attempt):", type(e), e)
        traceback.print_exc()

    # fallback: explicit SSLConnection using provided CA bundle
    try:
        print("Attempting explicit SSLConnection with CA:", cafile)
        r2 = redis.Redis.from_url(
            REDIS_URL,
            decode_responses=True,
            connection_class=redis.connection.SSLConnection,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            ssl_ca_certs=cafile,
            socket_keepalive=True,
            socket_connect_timeout=5
        )
        print("PING ->", r2.ping())
        k2 = f"test_key_sslconn_{int(time.time())}"
        r2.set(k2, "ok_sslconn")
        print("GET ->", r2.get(k2))
        return
    except Exception as e2:
        print("explicit SSLConnection failed:", type(e2), e2)
        traceback.print_exc()

def try_ssl_socket_handshake(cafile):
    print_hdr("Low-level SSL socket handshake test (using cafile)")
    host = REDIS_HOST or _host_from_url()
    port = REDIS_PORT or _port_from_url()
    if not host or not port:
        print("SKIP: host/port not available for SSL socket test")
        return
    try:
        ctx = ssl.create_default_context(cafile=cafile)
        # Optionally enforce TLS version if provider requires (example shown commented)
        # ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        raw = socket.create_connection((host, port), timeout=8)
        ss = ctx.wrap_socket(raw, server_hostname=host)
        print("TLS handshake ok. Cipher:", ss.cipher())
        peer = ss.getpeercert()
        print("Peer cert subject:", peer.get("subject") if peer else "None")
        print("Peer cert issuer:", peer.get("issuer") if peer else "None")
        # print SAN if present
        if peer:
            san = peer.get("subjectAltName")
            if san: print("SubjectAltName:", san)
        ss.close()
    except Exception as e:
        print("SSL socket handshake failed:", type(e), e)
        traceback.print_exc()

def _host_from_url():
    # simple parse to extract host from REDIS_URL if set (no password exposure)
    if not REDIS_URL: return None
    try:
        # URL format rediss://user:pass@host:port
        without_scheme = REDIS_URL.split("://",1)[1]
        # remove user:pass@
        if "@" in without_scheme:
            hostpart = without_scheme.split("@",1)[1]
        else:
            hostpart = without_scheme
        host = hostpart.split(":",1)[0]
        return host
    except:
        return None

def _port_from_url():
    if not REDIS_URL: return None
    try:
        without_scheme = REDIS_URL.split("://",1)[1]
        if "@" in without_scheme:
            hostpart = without_scheme.split("@",1)[1]
        else:
            hostpart = without_scheme
        parts = hostpart.split(":")
        if len(parts) >= 2:
            port = int(parts[1].split("/",1)[0])
            return port
        return None
    except:
        return None

def print_env_masked():
    print_hdr("ENVIRONMENT (masked)")
    print(json.dumps({
        "REDIS_HOST": REDIS_HOST or "(not set)",
        "REDIS_PORT": REDIS_PORT or "(not set)",
        "REDIS_USER": "(set)" if REDIS_USER else "(not set)",
        "REDIS_PASSWORD": "(set)" if REDIS_PASSWORD else "(not set)",
        "REDIS_URL": "(set)" if REDIS_URL else "(not set)",
        "REDIS_CA_B64": "(set)" if REDIS_CA_B64 else "(not set)"
    }, indent=2))

if __name__ == "__main__":
    print_env_masked()
    cafile = write_provider_ca_if_present()  # returns cafile path or certifi.where()
    # 1) plain (non-TLS)
    try_plain()
    # 2) secure from_url / sslconnection
    try_from_url_secure(cafile)
    # 3) low-level TLS handshake (helps debug SNI / cert mismatch)
    try_ssl_socket_handshake(cafile)
    print("\nDone tests.")
