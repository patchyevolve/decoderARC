import asyncio
import json
import logging

logger = logging.getLogger("coreids.broadcaster")

MAX_QUEUE_SIZE = 1000


class AlertBroadcaster:
    def __init__(self):
        self._subscribers: dict[str, list[asyncio.Queue]] = {}

    def subscribe(self, user_id: str, q: asyncio.Queue):
        if user_id not in self._subscribers:
            self._subscribers[user_id] = []
        self._subscribers[user_id].append(q)

    def unsubscribe(self, user_id: str, q: asyncio.Queue):
        subs = self._subscribers.get(user_id, [])
        if q in subs:
            subs.remove(q)
        if not subs:
            self._subscribers.pop(user_id, None)

    async def broadcast(self, user_id: str, message: dict):
        subs = self._subscribers.get(user_id, [])
        if not subs:
            return
        payload = json.dumps(message, default=str)
        for q in subs:
            try:
                if q.qsize() >= MAX_QUEUE_SIZE:
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                await q.put(payload)
            except Exception:
                pass

    async def broadcast_alert(self, user_id: str, alert_data: dict):
        await self.broadcast(user_id, {"type": "alert", "data": alert_data})

    async def broadcast_event(self, user_id: str, event_data: dict):
        await self.broadcast(user_id, {"type": "event", "data": event_data})

    async def broadcast_health(self, user_id: str, health_data: dict):
        await self.broadcast(user_id, {"type": "health", "data": health_data})


broadcaster = AlertBroadcaster()
