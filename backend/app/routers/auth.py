"""Auth routes: register, login, profile."""

from datetime import datetime, timezone

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..auth import hash_password, verify_password, create_jwt, get_current_user
from ..config import settings
from ..database import get_db
from ..models import User, Subscription
from ..ratelimit import login_limiter
from ..schemas import (
    RegisterRequest, LoginRequest, UserProfile, SubscriptionInfo, PlanInfo,
)

router = APIRouter(prefix="/api/auth", tags=["Auth"])


@router.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    # Rate limit register
    if not login_limiter.check(req.email):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")

    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=req.email,
        password_hash=hash_password(req.password),
        name=req.name,
        company=req.company,
    )
    db.add(user)
    db.flush()

    plan = settings.plans[settings.default_plan]
    sub = Subscription(
        user_id=user.id,
        plan=settings.default_plan,
        sensors_allowed=plan["sensors"],
        retention_days=plan["retention_days"],
        events_per_month_limit=plan["events_per_month"],
    )
    db.add(sub)
    db.commit()

    token = create_jwt(user.id, user.email)
    return _auth_response(token, user, settings.default_plan)


@router.post("/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    # Rate limit by email + IP
    client_ip = request.client.host if request.client else "unknown"
    ratelimit_key = f"{req.email}:{client_ip}"
    if not login_limiter.check(ratelimit_key):
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")

    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    # Reset rate limit on success
    login_limiter.clear(ratelimit_key)

    token = create_jwt(user.id, user.email)
    plan = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    return _auth_response(token, user, plan.plan if plan else "free")


def _auth_response(token: str, user: User, plan: str):
    """Build auth response with HttpOnly cookie for the JWT."""
    max_age = settings.jwt_expire_minutes * 60
    cookie_secure = os.getenv("COOKIE_SECURE", "false").lower() in ("true", "1", "yes")
    response = JSONResponse({
        "token": token,
        "user_id": user.id,
        "email": user.email,
        "name": user.name,
        "plan": plan,
    })
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=cookie_secure,
        samesite="strict",
        max_age=max_age,
        path="/",
    )
    return response


@router.post("/logout")
def logout():
    """Clear the HttpOnly auth cookie."""
    response = JSONResponse({"ok": True})
    response.set_cookie(
        key="access_token",
        value="",
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=0,
        path="/",
    )
    return response


@router.get("/me", response_model=UserProfile)
def get_profile(user: User = Depends(get_current_user)):
    return UserProfile(
        id=user.id, email=user.email, name=user.name,
        company=user.company, role=user.role, created_at=user.created_at,
    )


@router.get("/subscription", response_model=SubscriptionInfo)
def get_subscription(user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    sub = db.query(Subscription).filter(Subscription.user_id == user.id).first()
    if not sub:
        raise HTTPException(status_code=404, detail="No subscription found")
    return SubscriptionInfo(
        plan=sub.plan, status=sub.status,
        sensors_allowed=sub.sensors_allowed,
        retention_days=sub.retention_days,
        events_per_month_limit=sub.events_per_month_limit,
        current_period_end=sub.current_period_end,
    )


@router.get("/plans", response_model=list[PlanInfo])
def list_plans():
    return [
        PlanInfo(id=pid, **info)
        for pid, info in settings.plans.items()
    ]
