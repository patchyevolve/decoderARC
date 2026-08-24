import time
from collections import defaultdict
from threading import Lock


class RateLimiter:
    """In-memory sliding window rate limiter.

    Tracks attempts per key (e.g. email or IP) within a time window.
    Thread-safe for use with FastAPI's sync dependency injection.
    """
    def __init__(self, max_attempts: int = 5, window_s: int = 300):
        self.max_attempts = max_attempts
        self.window_s = window_s
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            self._attempts[key] = [
                t for t in self._attempts[key]
                if now - t < self.window_s
            ]
            if len(self._attempts[key]) >= self.max_attempts:
                return False
            self._attempts[key].append(now)
        return True

    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


login_limiter = RateLimiter(max_attempts=5, window_s=300)
