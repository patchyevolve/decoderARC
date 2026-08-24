"""Device management routes."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..auth import get_current_user, generate_api_key
from ..database import get_db
from ..models import User, Device, Subscription
from ..schemas import (
    DeviceCreate, DeviceResponse, DeviceUpdate,
    DeviceListItem, Message,
)

router = APIRouter(prefix="/api/devices", tags=["Devices"])

STALE_SECONDS = 120  # device offline if no heartbeat in this long


def _compute_status(d: Device) -> str:
    if not d.last_seen_at:
        return "offline"
    last = d.last_seen_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - last < timedelta(seconds=STALE_SECONDS):
        return "online"
    return "offline"


def _check_device_limit(user: User, db: Session):
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    allowed = sub.sensors_allowed if sub else 1
    count = db.query(Device).filter(Device.user_id == user.id).count()
    if count >= allowed:
        raise HTTPException(
            status_code=402,
            detail=f"Device limit ({allowed}) reached. Upgrade your plan.",
        )


@router.get("", response_model=list[DeviceListItem])
def list_devices(user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    devices = db.query(Device).filter(Device.user_id == user.id).all()
    return [
        DeviceListItem(
            id=d.id, name=d.name, status=_compute_status(d),
            last_seen_at=d.last_seen_at, version=d.version, ip=d.public_ip,
        )
        for d in devices
    ]


@router.post("", response_model=DeviceResponse)
def create_device(req: DeviceCreate,
                  user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    _check_device_limit(user, db)
    raw_key, key_hash, key_prefix = generate_api_key()
    device = Device(
        user_id=user.id,
        name=req.name or f"Sensor-{db.query(Device).filter(Device.user_id == user.id).count() + 1}",
        api_key_hash=key_hash,
        api_key_prefix=key_prefix,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return DeviceResponse(
        id=device.id, name=device.name, api_key=raw_key,
        status=_compute_status(device), last_seen_at=device.last_seen_at,
        version=device.version, location=device.location,
        created_at=device.created_at,
    )


@router.get("/{device_id}", response_model=DeviceResponse)
def get_device(device_id: str, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    device = db.query(Device).filter(
        Device.id == device_id, Device.user_id == user.id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return DeviceResponse(
        id=device.id, name=device.name, api_key="",
        status=_compute_status(device), last_seen_at=device.last_seen_at,
        version=device.version, location=device.location,
        created_at=device.created_at,
    )


@router.patch("/{device_id}", response_model=Message)
def update_device(device_id: str, req: DeviceUpdate,
                  user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    device = db.query(Device).filter(
        Device.id == device_id, Device.user_id == user.id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if req.name is not None:
        device.name = req.name
    if req.location is not None:
        device.location = req.location
    if req.config_json is not None:
        device.config_json = req.config_json
    db.commit()
    return Message(message="Device updated")


@router.delete("/{device_id}", response_model=Message)
def delete_device(device_id: str, user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    device = db.query(Device).filter(
        Device.id == device_id, Device.user_id == user.id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
    return Message(message="Device deleted")


@router.post("/{device_id}/regenerate-key", response_model=dict)
def regenerate_key(device_id: str, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    device = db.query(Device).filter(
        Device.id == device_id, Device.user_id == user.id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    raw_key, key_hash, key_prefix = generate_api_key()
    device.api_key_hash = key_hash
    device.api_key_prefix = key_prefix
    db.commit()
    return {"api_key": raw_key, "message": "Key regenerated — update your daemon"}


@router.get("/{device_id}/test-connection")
def test_device_connection(device_id: str,
                           user: User = Depends(get_current_user),
                           db: Session = Depends(get_db)):
    device = db.query(Device).filter(
        Device.id == device_id, Device.user_id == user.id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    real_status = _compute_status(device)
    online = real_status == "online"
    since = ""
    if device.last_seen_at:
        last = device.last_seen_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - last
        mins = int(delta.total_seconds() // 60)
        if mins < 1:
            since = "just now"
        elif mins < 60:
            since = f"{mins} minutes ago"
        else:
            since = f"{mins // 60}h {mins % 60}m ago"
    return {
        "online": online,
        "status": real_status,
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
        "last_seen_human": since,
        "version": device.version,
        "message": "Device is connected and sending heartbeats" if online
                   else "Device is offline. Make sure the daemon is running with the correct device_id and api_key.",
    }
