"""Detection rules management routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import User, Rule
from ..schemas import RuleCreate, RuleResponse, RuleListResponse, Message

router = APIRouter(prefix="/api/rules", tags=["Rules"])


def _next_sid(db: Session, user_id: str) -> int:
    max_sid = db.query(func.max(Rule.sid)).filter(Rule.user_id == user_id).scalar()
    return (max_sid or 1000000) + 1


@router.get("", response_model=RuleListResponse)
def list_rules(
    search: str = "",
    category: str = "",
    severity: str = "",
    status: str = "",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Rule).filter(Rule.user_id == user.id)
    if search:
        like = f"%{search}%"
        q = q.filter(Rule.name.ilike(like) | Rule.category.ilike(like))
    if category:
        q = q.filter(Rule.category == category)
    if severity:
        q = q.filter(Rule.severity == severity)
    if status == "Enabled":
        q = q.filter(Rule.enabled)
    elif status == "Disabled":
        q = q.filter(~Rule.enabled)
    q = q.order_by(Rule.sid.asc())
    rules = q.all()
    total = len(rules)
    active = sum(1 for r in rules if r.enabled)
    disabled = total - active
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    triggered_today = sum(
        1 for r in rules
        if r.last_hit and r.last_hit >= today
    )
    return RuleListResponse(
        rules=[
            {
                "id": r.id, "sid": r.sid, "name": r.name,
                "category": r.category, "severity": r.severity,
                "protocol": r.protocol, "action": r.action,
                "enabled": r.enabled, "triggers": r.triggers,
                "last_hit": r.last_hit.strftime("%H:%M:%S") if r.last_hit else "",
            }
            for r in rules
        ],
        total=total,
        active=active,
        disabled=disabled,
        triggered_today=triggered_today,
        triggered_trend=0.0,
    )


@router.post("", response_model=RuleResponse)
def create_rule(req: RuleCreate,
                user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    rule = Rule(
        sid=_next_sid(db, user.id),
        user_id=user.id,
        name=req.name,
        category=req.category,
        severity=req.severity,
        protocol=req.protocol,
        action=req.action,
        condition=req.condition,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return RuleResponse(
        id=rule.id, sid=rule.sid, name=rule.name,
        category=rule.category, severity=rule.severity,
        protocol=rule.protocol, action=rule.action,
        enabled=rule.enabled, triggers=rule.triggers,
        last_hit="",
    )


@router.put("/{rule_id}", response_model=Message)
def update_rule(rule_id: str, req: RuleCreate,
                user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    rule = db.query(Rule).filter(
        Rule.id == rule_id, Rule.user_id == user.id
    ).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.name = req.name
    rule.category = req.category
    rule.severity = req.severity
    rule.protocol = req.protocol
    rule.action = req.action
    rule.condition = req.condition
    db.commit()
    return Message(message="Rule updated")


@router.delete("/{rule_id}", response_model=Message)
def delete_rule(rule_id: str,
                user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    rule = db.query(Rule).filter(
        Rule.id == rule_id, Rule.user_id == user.id
    ).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    return Message(message="Rule deleted")


@router.patch("/{rule_id}/toggle", response_model=Message)
def toggle_rule(rule_id: str,
                user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    rule = db.query(Rule).filter(
        Rule.id == rule_id, Rule.user_id == user.id
    ).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled = not rule.enabled
    db.commit()
    return Message(message=f"Rule {'enabled' if rule.enabled else 'disabled'}")


@router.get("/export")
def export_rules(user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    rules = db.query(Rule).filter(Rule.user_id == user.id).order_by(Rule.sid).all()
    data = [
        {"sid": r.sid, "name": r.name, "category": r.category,
         "severity": r.severity, "protocol": r.protocol,
         "action": r.action, "condition": r.condition, "enabled": r.enabled}
        for r in rules
    ]
    import json
    return Response(
        content=json.dumps(data, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="coreids_rules.json"'},
    )


@router.post("/import")
def import_rules(req: list[RuleCreate],
                 user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    created = []
    for r in req:
        rule = Rule(
            sid=_next_sid(db, user.id),
            user_id=user.id,
            name=r.name, category=r.category,
            severity=r.severity, protocol=r.protocol,
            action=r.action, condition=r.condition,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        created.append(rule.id)
    return {"imported": len(created), "ids": created}
