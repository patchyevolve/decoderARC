import asyncio
import logging
import threading
import time
from collections import defaultdict, deque

from .broadcaster import broadcaster
from .database import SessionLocal
from .models import TrafficEvent, Alert, LogEntry, Device
from sqlalchemy import text

logger = logging.getLogger("coreids.runtime")

# Try to load the C central IDS bridge; fall back to placeholder if unavailable
try:
    from .ids_bridge import get_runtime as _get_c_runtime
    _c_runtime_available = True
except Exception:
    _c_runtime_available = False

_PROTO_MAP = {
    "TCP": 6, "UDP": 17, "ICMP": 1, "ICMPV6": 58,
    6: 6, 17: 17, 1: 1, 58: 58,
}

# Max events per user queue before oldest are dropped
MAX_USER_QUEUE = 10000


def _proto_to_int(proto: str) -> int:
    p = proto.upper().strip() if proto else ""
    return _PROTO_MAP.get(p, 0)


class UserRuntime:
    def __init__(self, user_id: str, loop: asyncio.AbstractEventLoop):
        self.user_id = user_id
        self.loop = loop
        self.lock = threading.Lock()
        self.queue: deque[TrafficEvent] = deque(maxlen=MAX_USER_QUEUE)

    def ingest(self, event: TrafficEvent):
        with self.lock:
            if len(self.queue) >= MAX_USER_QUEUE:
                self.queue.popleft()  # drop oldest
            self.queue.append(event)

    def process_batch(self, db, event_ids_for_mark: list[str] | None = None):
        batch = []
        with self.lock:
            while self.queue:
                batch.append(self.queue.popleft())

        if not batch:
            return

        alerts = []
        c_alerts: list[dict] = []
        logs = []

        # Batch C bridge call: group all events and call once per user
        batch_alerts_by_event: dict[str, dict] = {}
        if _c_runtime_available and batch:
            try:
                c_runtime = _get_c_runtime()
                user_id = batch[0].user_id  # all events in this batch belong to same user
                bridge_events = [
                    {
                        "src_ip": e.src_ip,
                        "src_port": e.src_port,
                        "dst_ip": e.dst_ip,
                        "dst_port": e.dst_port,
                        "protocol": _proto_to_int(e.protocol),
                        "bytes": e.bytes,
                        "event_type": e.event_type,
                        "timestamp": e.time.timestamp() if e.time else time.time(),
                    }
                    for e in batch
                ]
                c_alerts = c_runtime.ingest_batch(user_id, bridge_events)
                # Map alerts back to events by index
                for i, ev in enumerate(batch):
                    if i < len(c_alerts) and c_alerts[i]:
                        batch_alerts_by_event[ev.id] = c_alerts[i]
            except Exception as exc:
                logger.error("Bridge batch error for %s: %s", batch[0].user_id, exc)

        for ev in batch:
            alert_data = batch_alerts_by_event.get(ev.id)

            if alert_data:
                device = db.query(Device).filter(Device.id == ev.device_id).first()
                device_name = device.name if device else "unknown"
                decision = alert_data.get("decision", "alert")
                severity = alert_data.get("severity", "medium")
                attack_class = alert_data.get("attack_class", "")

                alert = Alert(
                    user_id=ev.user_id,
                    device_id=ev.device_id,
                    time=ev.time,
                    decision=decision,
                    severity=severity,
                    confidence=alert_data.get("confidence", 0.0),
                    source_ip=ev.src_ip,
                    dest_ip=ev.dst_ip,
                    source_port=ev.src_port,
                    dest_port=ev.dst_port,
                    protocol=ev.protocol,
                    attack_class=attack_class,
                    anomaly_score=alert_data.get("confidence", 0.0),
                    ae_score=0.0,
                    explanation=alert_data.get("explanation", ""),
                )
                alerts.append(alert)
                logs.append(LogEntry(
                    user_id=ev.user_id,
                    device_id=ev.device_id,
                    time=ev.time,
                    type="Alert",
                    protocol=ev.protocol,
                    src_ip=ev.src_ip,
                    src_port=ev.src_port,
                    dst_ip=ev.dst_ip,
                    dst_port=ev.dst_port,
                    severity=severity,
                    message=attack_class or "Central IDS alert",
                    device_name=device_name,
                ))
            elif ev.bytes > 1_000_000:
                device = db.query(Device).filter(Device.id == ev.device_id).first()
                device_name = device.name if device else "unknown"
                alert = Alert(
                    user_id=ev.user_id,
                    device_id=ev.device_id,
                    time=ev.time,
                    decision="alert",
                    severity="high",
                    confidence=0.9,
                    source_ip=ev.src_ip,
                    dest_ip=ev.dst_ip,
                    source_port=ev.src_port,
                    dest_port=ev.dst_port,
                    protocol=ev.protocol,
                    attack_class="large_traffic",
                    anomaly_score=1.0,
                    ae_score=0.0,
                    explanation=f"Large traffic volume: {ev.bytes} bytes",
                )
                alerts.append(alert)
                logs.append(LogEntry(
                    user_id=ev.user_id,
                    device_id=ev.device_id,
                    time=ev.time,
                    type="Network",
                    protocol=ev.protocol,
                    src_ip=ev.src_ip,
                    src_port=ev.src_port,
                    dst_ip=ev.dst_ip,
                    dst_port=ev.dst_port,
                    severity="info",
                    message=f"Alert for {ev.src_ip}->{ev.dst_ip} bytes={ev.bytes}",
                    device_name=device_name,
                ))

        if alerts:
            db.add_all(alerts)
        if logs:
            db.add_all(logs)

        # Mark events as processed in the SAME transaction
        if event_ids_for_mark:
            db.query(TrafficEvent).filter(TrafficEvent.id.in_(event_ids_for_mark)).update(
                {TrafficEvent.processed: True}, synchronize_session=False
            )

        if alerts or logs or event_ids_for_mark:
            db.commit()

        if alerts:
            for a in alerts:
                try:
                    asyncio.run_coroutine_threadsafe(
                        broadcaster.broadcast_alert(a.user_id, {
                            "id": a.id,
                            "time": str(a.time),
                            "decision": a.decision,
                            "severity": a.severity,
                            "source_ip": a.source_ip,
                            "dest_ip": a.dest_ip,
                            "attack_class": a.attack_class,
                        }),
                        self.loop
                    )
                except Exception:
                    pass


class UserRuntimeManager:
    def __init__(self, num_workers: int = 4):
        self.runtimes: dict[str, UserRuntime] = {}
        self.lock = threading.Lock()
        self._running = False
        self._worker_threads: list[threading.Thread] = []
        self._num_workers = max(1, num_workers)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None

    def get_runtime(self, user_id: str) -> UserRuntime:
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
        loop = self._loop
        with self.lock:
            if user_id not in self.runtimes:
                self.runtimes[user_id] = UserRuntime(user_id, loop)
            return self.runtimes[user_id]

    def ingest_events(self, events: list[TrafficEvent]):
        user_events = defaultdict(list)
        for ev in events:
            user_events[ev.user_id].append(ev)

        for user_id, user_event_list in user_events.items():
            runtime = self.get_runtime(user_id)
            for ev in user_event_list:
                runtime.ingest(ev)

    @staticmethod
    def _partition_for(user_id: str, num_workers: int) -> int:
        return abs(hash(user_id)) % num_workers

    def start(self):
        if self._running:
            return
        self._running = True

        # Start shared event loop for async operations
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._loop_thread.start()

        if _c_runtime_available:
            try:
                _get_c_runtime().start()
                logger.info("C central IDS bridge started")
            except Exception as e:
                logger.warning("Failed to start C bridge: %s", e)
        else:
            logger.info("C bridge unavailable, using placeholder detection")

        # Start N partition-based workers
        self._worker_threads = []
        for i in range(self._num_workers):
            w = threading.Thread(
                target=self._worker_loop,
                args=(i,),
                daemon=True,
            )
            w.start()
            self._worker_threads.append(w)
        logger.info("Started %d runtime workers", self._num_workers)

    def stop(self):
        self._running = False
        for w in self._worker_threads:
            w.join(timeout=5)
        if self._loop and self._loop_thread:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._loop_thread.join(timeout=5)
        if _c_runtime_available:
            try:
                _get_c_runtime().stop()
            except Exception:
                pass

    def _worker_loop(self, worker_id: int):
        """Worker processes only events whose user_id hashes to its partition."""
        while self._running:
            try:
                self._process_batch_partition(worker_id)
                time.sleep(0.1)
            except Exception as e:
                logger.error("Worker %d error: %s", worker_id, e)
                time.sleep(5)

    def _process_batch_partition(self, worker_id: int):
        db = SessionLocal()
        try:
            # Quick health check — silently skip if DB is unreachable
            try:
                db.execute(text("SELECT 1"))
            except Exception:
                return
            # Fetch unprocessed events — each worker uses its own session
            events = db.query(TrafficEvent).filter(
                ~TrafficEvent.processed
            ).limit(200).all()

            if not events:
                return

            # Filter to this worker's partition
            my_events = [
                ev for ev in events
                if self._partition_for(ev.user_id, self._num_workers) == worker_id
            ]
            if not my_events:
                return

            # Atomically claim events for this worker to prevent double-processing
            my_ids = [ev.id for ev in my_events]
            db.query(TrafficEvent).filter(
                TrafficEvent.id.in_(my_ids),
                ~TrafficEvent.processed,
            ).update(
                {TrafficEvent.processed: True}, synchronize_session=False
            )
            db.commit()

            # Route claimed events to per-user runtimes
            self.ingest_events(my_events)

            # Process all runtimes that have queued events
            # Pass event IDs for atomic processed marking within the same transaction
            with self.lock:
                for runtime in self.runtimes.values():
                    runtime.process_batch(db, event_ids_for_mark=my_ids)
        except Exception as e:
            db.rollback()
            logger.error("Worker %d batch error: %s", worker_id, e)
        finally:
            db.close()
