import time
import logging
from enum import Enum
from typing import Callable

logger = logging.getLogger("coreids.circuit_breaker")


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpenError(Exception):
    pass


class CircuitBreaker:
    """Thread-safe circuit breaker for external dependencies.

    States:
        CLOSED — normal operation, calls pass through
        OPEN — failures exceeded threshold, calls are rejected immediately
        HALF_OPEN — after recovery timeout, a limited number of test calls proceed
    """
    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_timeout_s: float = 30.0,
        half_open_max: int = 3,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout_s = recovery_timeout_s
        self.half_open_max = half_open_max

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._half_open_attempts = 0

    @property
    def state(self) -> CircuitState:
        return self._state

    def call(self, func: Callable, *args, **kwargs):
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time >= self.recovery_timeout_s:
                logger.info("Circuit %s: transitioning OPEN -> HALF_OPEN", self.name)
                self._state = CircuitState.HALF_OPEN
                self._half_open_attempts = 0
            else:
                raise CircuitBreakerOpenError(
                    f"Circuit {self.name} is OPEN. "
                    f"Retry in {self.recovery_timeout_s - (time.time() - self._last_failure_time):.0f}s"
                )

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            raise

    def _on_success(self):
        if self._state == CircuitState.HALF_OPEN:
            self._half_open_attempts += 1
            if self._half_open_attempts >= self.half_open_max:
                logger.info("Circuit %s: HALF_OPEN -> CLOSED (all test calls passed)", self.name)
                self._state = CircuitState.CLOSED
                self._failure_count = 0
        else:
            self._failure_count = 0

    def _on_failure(self):
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self.failure_threshold:
            logger.warning(
                "Circuit %s: CLOSED -> OPEN (%d failures)",
                self.name, self._failure_count
            )
            self._state = CircuitState.OPEN

    def reset(self):
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_attempts = 0
