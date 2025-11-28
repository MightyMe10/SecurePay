"""Blueprints containing all HTTP endpoints."""
from __future__ import annotations

import secrets
import string
from datetime import datetime, timezone
from decimal import Decimal
from typing import List

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from .decorators import role_required
from .extensions import db
from .forms import (
    AdminFreezeForm,
    AdminResetPasswordForm,
    BeneficiaryDeleteForm,
    BeneficiaryForm,
    LoginForm,
    PasswordResetForm,
    RegistrationForm,
    SessionTerminateForm,
    TransferForm,
)
from .models import Account, ActiveSession, Beneficiary, Transaction, User
from .security import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    generate_totp_secret,
    hash_password,
    needs_rehash,
    verify_password,
    verify_totp,
)


auth_bp = Blueprint("auth", __name__)
portal_bp = Blueprint("portal", __name__)


ROUTE_LOGIN = "auth.login"
ROUTE_DASHBOARD = "portal.dashboard"
ROUTE_BENEFICIARIES = "portal.beneficiaries"
ROUTE_ADMIN = "portal.admin_panel"
ROUTE_DEVICES = "portal.devices"

TEMPLATE_LOGIN = "login.html"
TEMPLATE_TRANSFER = "transfer.html"


def _primary_account() -> Account | None:
    return current_user.accounts[0] if current_user.accounts else None


def _current_session_record() -> ActiveSession | None:
    token = session.get("session_token")
    if not token or not current_user.is_authenticated:
        return None
    return ActiveSession.query.filter_by(session_token=token, user_id=current_user.id, is_active=True).first()


def _register_session(user: User) -> None:
    user_agent = (request.user_agent.string or "unknown")[:255]
    ip_address = (request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown")[:64]
    record = ActiveSession(user=user, user_agent=user_agent, ip_address=ip_address)
    db.session.add(record)
    db.session.flush()
    session["session_token"] = record.session_token


def _generate_temp_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and any(c in "!@#$%^&*()-_=+" for c in candidate)
        ):
            return candidate


def _record_auth_failure(user: User) -> None:
    user.failed_attempts = (user.failed_attempts or 0) + 1
    user.last_failed_at = datetime.now(timezone.utc)
    db.session.commit()


@portal_bp.before_app_request
def refresh_active_session():
    if not current_user.is_authenticated:
        return None
    record = _current_session_record()
    if not record:
        session.pop("session_token", None)
        logout_user()
        flash("Your session has ended. Please sign in again.", "warning")
        return redirect(url_for(ROUTE_LOGIN))
    record.last_seen = datetime.now(timezone.utc)
    db.session.commit()
    return None


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for(ROUTE_DASHBOARD))
    form = RegistrationForm()
    if form.validate_on_submit():
        secret = generate_totp_secret()
        encrypted_secret = encrypt_totp_secret(secret)
        try:
            user = User(
                email=form.email.data.lower(),
                full_name=form.full_name.data.strip(),
                password_hash=hash_password(form.password.data),
                totp_secret_encrypted=encrypted_secret,
            )
            db.session.add(user)
            db.session.flush()
            account = Account(account_number=Account.generate_account_number(), owner=user)
            db.session.add(account)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Email already registered.", "danger")
        else:
            provisioning_uri = f"otpauth://totp/Secure%20Pay:{user.email}?secret={secret}&issuer=Secure%20Pay"
            flash("Account created. Store the MFA secret in your authenticator app.", "success")
            return render_template("mfa_setup.html", secret=secret, provisioning_uri=provisioning_uri, email=user.email)
    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for(ROUTE_DASHBOARD))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if not user:
            flash("Invalid credentials.", "danger")
            return render_template(TEMPLATE_LOGIN, form=form)
        if not user.is_active:
            flash("Account is frozen. Contact support.", "danger")
            return render_template(TEMPLATE_LOGIN, form=form)

        if _is_account_locked(user):
            return render_template(TEMPLATE_LOGIN, form=form)

        if not _verify_credentials_and_mfa(user, form):
            return render_template(TEMPLATE_LOGIN, form=form)

        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(form.password.data, enforce_policy=False)

        user.failed_attempts = 0
        user.last_failed_at = None
        user.last_login_at = datetime.now(timezone.utc)

        login_user(user, remember=form.remember_me.data, duration=config["PERMANENT_SESSION_LIFETIME"])
        _register_session(user)
        db.session.commit()
        flash("Logged in securely.", "success")
        return redirect(url_for(ROUTE_DASHBOARD))
    return render_template(TEMPLATE_LOGIN, form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    record = _current_session_record()
    if record:
        record.terminate()
        db.session.commit()
    session.pop("session_token", None)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for(ROUTE_LOGIN))


@portal_bp.route("/")
@login_required
def root():
    return redirect(url_for(ROUTE_DASHBOARD))


@portal_bp.route("/dashboard")
@login_required
def dashboard():
    account = _primary_account()
    recent_transactions: List[Transaction] = []
    if account:
        recent_transactions = (
            Transaction.query.filter_by(account_id=account.id)
            .order_by(Transaction.created_at.desc())
            .limit(5)
            .all()
        )
    return render_template("dashboard.html", account=account, transactions=recent_transactions)


@portal_bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    account = _primary_account()
    if not account:
        flash("No active account assigned.", "warning")
        return redirect(url_for(ROUTE_DASHBOARD))
    form = TransferForm()
    saved_beneficiaries = Beneficiary.query.filter_by(user_id=current_user.id).order_by(Beneficiary.nickname).all()
    if form.validate_on_submit():
        amount = Decimal(form.amount.data)
        target_account = Account.query.filter_by(account_number=form.target_account.data).first()
        if not target_account:
            flash("Recipient account not found.", "warning")
            return render_template(
                TEMPLATE_TRANSFER, form=form, account=account, beneficiaries=saved_beneficiaries
            )
        if target_account.id == account.id:
            flash("Cannot transfer to the same account.", "warning")
            return render_template(
                TEMPLATE_TRANSFER, form=form, account=account, beneficiaries=saved_beneficiaries
            )
        try:
            account.debit(amount)
            target_account.credit(amount)
            description = (form.description.data or "").strip()
            Transaction.record(
                account=account,
                counterparty_account=target_account.account_number,
                amount=amount,
                description=description,
                direction="debit",
            )
            Transaction.record(
                account=target_account,
                counterparty_account=account.account_number,
                amount=amount,
                description=description,
                direction="credit",
            )
            db.session.commit()
        except ValueError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            flash("Transfer completed.", "success")
            return redirect(url_for(ROUTE_DASHBOARD))
    return render_template(TEMPLATE_TRANSFER, form=form, account=account, beneficiaries=saved_beneficiaries)


@portal_bp.route("/transactions")
@login_required
def transactions():
    account = _primary_account()
    if not account:
        flash("No active account assigned.", "warning")
        return redirect(url_for(ROUTE_DASHBOARD))
    history = (
        Transaction.query.filter_by(account_id=account.id)
        .order_by(Transaction.created_at.desc())
        .all()
    )
    return render_template("transactions.html", account=account, transactions=history)


@portal_bp.route("/beneficiaries", methods=["GET", "POST"])
@login_required
def beneficiaries():
    form = BeneficiaryForm()
    beneficiaries_list = (
        Beneficiary.query.filter_by(user_id=current_user.id)
        .order_by(Beneficiary.created_at.desc())
        .all()
    )
    delete_form = BeneficiaryDeleteForm()
    if form.validate_on_submit():
        existing = Beneficiary.query.filter_by(
            user_id=current_user.id, account_number=form.account_number.data
        ).first()
        if existing:
            flash("Beneficiary already saved.", "warning")
        else:
            entry = Beneficiary(
                owner=current_user,
                nickname=form.nickname.data.strip(),
                account_number=form.account_number.data,
            )
            db.session.add(entry)
            db.session.commit()
            flash("Beneficiary saved.", "success")
            return redirect(url_for(ROUTE_BENEFICIARIES))
    return render_template(
        "beneficiaries.html",
        form=form,
        beneficiaries=beneficiaries_list,
        delete_form=delete_form,
    )


@portal_bp.route("/beneficiaries/<int:beneficiary_id>/delete", methods=["POST"])
@login_required
def delete_beneficiary(beneficiary_id: int):
    form = BeneficiaryDeleteForm()
    if not form.validate_on_submit() or int(form.beneficiary_id.data) != beneficiary_id:
        flash("Invalid request.", "danger")
        return redirect(url_for(ROUTE_BENEFICIARIES))
    entry = Beneficiary.query.filter_by(id=beneficiary_id, user_id=current_user.id).first()
    if not entry:
        flash("Beneficiary not found.", "warning")
        return redirect(url_for(ROUTE_BENEFICIARIES))
    db.session.delete(entry)
    db.session.commit()
    flash("Beneficiary removed.", "info")
    return redirect(url_for(ROUTE_BENEFICIARIES))


@portal_bp.route("/devices", methods=["GET", "POST"])
@login_required
def devices():
    form = SessionTerminateForm()
    sessions_list = (
        ActiveSession.query.filter_by(user_id=current_user.id)
        .order_by(ActiveSession.last_seen.desc())
        .all()
    )
    if form.validate_on_submit():
        record = ActiveSession.query.filter_by(
            id=int(form.session_id.data), user_id=current_user.id
        ).first()
        if not record:
            flash("Session not found.", "warning")
            return redirect(url_for(ROUTE_DEVICES))
        record.terminate()
        db.session.commit()
        if record.session_token == session.get("session_token"):
            session.pop("session_token", None)
            logout_user()
            flash("Current session terminated. Please log in again.", "info")
            return redirect(url_for(ROUTE_LOGIN))
        flash("Device session logged out.", "success")
        return redirect(url_for(ROUTE_DEVICES))
    return render_template("devices.html", sessions=sessions_list, form=form)


@portal_bp.route("/settings/password", methods=["GET", "POST"])
@login_required
def password_settings():
    form = PasswordResetForm()
    if form.validate_on_submit():
        if not verify_password(current_user.password_hash, form.current_password.data):
            flash("Current password is incorrect.", "danger")
        else:
            totp_secret = decrypt_totp_secret(current_user.totp_secret_encrypted)
            if not totp_secret or not verify_totp(form.totp_code.data, totp_secret):
                flash("Invalid MFA code.", "danger")
            else:
                current_user.password_hash = hash_password(form.new_password.data)
                db.session.commit()
                flash("Password updated securely.", "success")
                return redirect(url_for(ROUTE_DASHBOARD))
    return render_template("password_reset.html", form=form)


@portal_bp.route("/admin")
@role_required("admin")
def admin_panel():
    users = User.query.order_by(User.created_at.desc()).all()
    accounts = Account.query.order_by(Account.created_at.desc()).all()
    freeze_form = AdminFreezeForm()
    reset_form = AdminResetPasswordForm()
    return render_template(
        "admin.html",
        users=users,
        accounts=accounts,
        freeze_form=freeze_form,
        reset_form=reset_form,
    )


@portal_bp.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@role_required("admin")
def admin_toggle_user(user_id: int):
    form = AdminFreezeForm()
    if not form.validate_on_submit() or int(form.user_id.data) != user_id:
        abort(400)
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot change your own status.", "warning")
        return redirect(url_for(ROUTE_ADMIN))
    if user.is_active:
        if user.role == "admin":
            active_admins = User.query.filter_by(role="admin", is_active=True).count()
            if active_admins <= 1:
                flash("Cannot freeze the last active admin.", "danger")
                return redirect(url_for(ROUTE_ADMIN))
        user.is_active = False
        message = "User frozen."
    else:
        user.is_active = True
        message = "User reactivated."
    db.session.commit()
    flash(message, "info")
    return redirect(url_for(ROUTE_ADMIN))


@portal_bp.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@role_required("admin")
def admin_reset_user_password(user_id: int):
    form = AdminResetPasswordForm()
    if not form.validate_on_submit() or int(form.user_id.data) != user_id:
        abort(400)
    user = User.query.get_or_404(user_id)
    temp_password = _generate_temp_password()
    user.password_hash = hash_password(temp_password)
    db.session.commit()
    flash(
        f"Temporary password for {user.email}: {temp_password}. Share securely and require immediate reset.",
        "info",
    )
    return redirect(url_for(ROUTE_ADMIN))
