"""
Redis connectivity test (non-TLS mode, works with free Redis Cloud 30MB plan)
"""

import os
import redis
import json

def main():
    # Environment मधून values घे
    host = os.getenv("REDIS_HOST", "redis-14246.crce206.ap-south-1-1.ec2.redns.redis-cloud.com")
    port = int(os.getenv("REDIS_PORT", "14246"))
    user = os.getenv("REDIS_USER", "default")
    password = os.getenv("REDIS_PASSWORD", "")

    print("====== ENVIRONMENT (masked) ======")
    masked = {
        "REDIS_HOST": host,
        "REDIS_PORT": port,
        "REDIS_USER": user,
        "REDIS_PASSWORD": "(set)" if password else "(empty)",
    }
    print(json.dumps(masked, indent=2))

    print("====== PLAIN (non-TLS) connection test ======")
    try:
        r = redis.Redis(
            host=host,
            port=port,
            username=user,
            password=password,
            decode_responses=True
        )
        print("PING ->", r.ping())
        key = "foo:test"
        r.set(key, "bar")
        print("GET ->", r.get(key))
    except Exception as e:
        print("ERROR:", e)

    print("Done tests.")

if __name__ == "__main__":
    main()
