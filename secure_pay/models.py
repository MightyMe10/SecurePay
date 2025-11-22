"""Database models for Secure Pay."""
from __future__ import annotations

import secrets
from datetime import datetime
from decimal import Decimal
from uuid import uuid4

from flask_login import UserMixin

from .extensions import db


class TimestampMixin:
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class User(UserMixin, TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)
    totp_secret_encrypted = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    failed_attempts = db.Column(db.Integer, default=0)
    last_failed_at = db.Column(db.DateTime)
    last_login_at = db.Column(db.DateTime)

    accounts = db.relationship("Account", backref="owner", lazy=True)
    beneficiaries = db.relationship("Beneficiary", backref="owner", lazy=True, cascade="all, delete-orphan")
    sessions = db.relationship("ActiveSession", backref="user", lazy=True, cascade="all, delete-orphan")

    def has_role(self, role: str) -> bool:
        return self.role.lower() == role.lower()


class Account(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    balance = db.Column(db.Numeric(14, 2), default=Decimal("0.00"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    outgoing_transactions = db.relationship(
        "Transaction",
        backref="account",
        lazy=True,
        foreign_keys="Transaction.account_id",
    )

    def credit(self, amount: Decimal) -> None:
        if amount <= 0:
            raise ValueError("Amount must be positive")
        self.balance += amount

    def debit(self, amount: Decimal) -> None:
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if amount > self.balance:
            raise ValueError("Insufficient balance")
        self.balance -= amount

    @staticmethod
    def generate_account_number() -> str:
        candidate = f"10{secrets.randbelow(10**10):010d}"
        while Account.query.filter_by(account_number=candidate).first():
            candidate = f"10{secrets.randbelow(10**10):010d}"
        return candidate


class Transaction(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey("account.id"), nullable=False)
    counterparty_account = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Numeric(14, 2), nullable=False)
    description = db.Column(db.String(255))
    direction = db.Column(db.String(10), nullable=False)  # debit or credit

    @classmethod
    def record(
        cls,
        *,
        account: Account,
        counterparty_account: str,
        amount: Decimal,
        description: str,
        direction: str,
    ) -> "Transaction":
        entry = cls(
            account=account,
            counterparty_account=counterparty_account,
            amount=amount,
            description=description,
            direction=direction,
        )
        db.session.add(entry)
        return entry


class Beneficiary(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(120), nullable=False)
    account_number = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    __table_args__ = (db.UniqueConstraint("user_id", "account_number", name="uq_user_beneficiary"),)


class ActiveSession(TimestampMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_token = db.Column(db.String(64), unique=True, nullable=False, default=lambda: uuid4().hex)
    user_agent = db.Column(db.String(255))
    ip_address = db.Column(db.String(64))
    is_active = db.Column(db.Boolean, default=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def terminate(self) -> None:
        self.is_active = False
        timestamp = datetime.utcnow()
        self.ended_at = timestamp
        self.last_seen = timestamp
