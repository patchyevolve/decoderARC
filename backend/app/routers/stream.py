import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends, Request
from fastapi.responses import StreamingResponse

from ..auth import get_current_user, decode_jwt
from ..models import User
from ..broadcaster import broadcaster

router = APIRouter(tags=["Stream"])


@router.get("/stream/alerts")
async def stream_alerts(
    request: Request,
    user: User = Depends(get_current_user),
):
    """SSE endpoint streaming new alerts for the authenticated user."""
    q: asyncio.Queue = asyncio.Queue()
    broadcaster.subscribe(user.id, q)

    async def event_generator():
        try:
            while True:
                payload = await q.get()
                yield f"data: {payload}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            broadcaster.unsubscribe(user.id, q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.websocket("/ws/alerts")
async def ws_alerts(
    websocket: WebSocket,
    token: str = Query(...),
):
    """WebSocket endpoint for real-time alerts. Auth via JWT token query param."""
    payload = decode_jwt(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid token")
        return

    # Check token expiry
    exp = payload.get("exp")
    if exp and datetime.now(timezone.utc).timestamp() > exp:
        await websocket.close(code=4001, reason="Token expired")
        return

    user_id = payload.get("sub")

    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue()
    broadcaster.subscribe(user_id, q)

    try:
        while True:
            payload = await q.get()
            await websocket.send_text(payload)
    except WebSocketDisconnect:
        pass
    finally:
        broadcaster.unsubscribe(user_id, q)


@router.get("/stream/health")
async def stream_health(
    request: Request,
    user: User = Depends(get_current_user),
):
    """SSE endpoint streaming health updates for the user's devices."""
    q: asyncio.Queue = asyncio.Queue()
    broadcaster.subscribe(user.id, q)

    async def event_generator():
        try:
            while True:
                payload = await q.get()
                yield f"data: {payload}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            broadcaster.unsubscribe(user.id, q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
