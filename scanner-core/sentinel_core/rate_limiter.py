import time
import redis

class RateLimiter:
    """
    Redis DECR komutu atomic olduğu için race condition olmaz.
    """
    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379,
                 max_tokens: int = 5, refill_interval: float = 1.0):
        self.redis = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        # Saniyede maksimum kaç istek
        self.max_tokens = max_tokens
        # Kaç saniyede bir token eklenir
        self.refill_interval = refill_interval

    def _bucket_key(self, domain: str) -> str:
        """Redis key — ratelimit:{domain}"""
        return f"ratelimit:{domain}"

    def acquire(self, domain: str) -> None:
        key = self._bucket_key(domain)

        while True:
            if not self.redis.exists(key):
                self.redis.set(key, self.max_tokens, ex=60, nx=True)

            remaining = self.redis.decr(key)

            if remaining >= 0:
                return
            else:
                self.redis.set(key, 0)
                time.sleep(self.refill_interval)
                # Yeni token ekle
                self.redis.set(key, self.max_tokens, ex=60)
