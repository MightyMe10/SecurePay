"""Secure Pay Flask application factory."""
from __future__ import annotations

import click
from flask import Flask
from getpass import getpass
import logging
import os

from .config import get_config
from .extensions import csrf, db, login_manager
from .models import User
from .routes import auth_bp, portal_bp
from .security import (
    encrypt_totp_secret,
    generate_totp_secret,
    hash_password,
    PasswordPolicyError,
)


def _prompt_for_password() -> str:
    while True:
        password = getpass("Password: ")
        try:
            return hash_password(password)
        except PasswordPolicyError as exc:
            click.echo(f"Password rejected: {exc}")


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=False)
    config_class = get_config(config_name or os.getenv("FLASK_ENV"))
    app.config.from_object(config_class)

    register_extensions(app)
    register_blueprints(app)
    register_security_headers(app)
    register_cli(app)

    return app


def register_extensions(app: Flask) -> None:
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:
        return User.query.get(int(user_id))


def register_blueprints(app: Flask) -> None:
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(portal_bp)


def register_security_headers(app: Flask) -> None:
    @app.after_request
    def apply_headers(response):
        # Enforce a restrictive CSP and complementary hardening headers per response.
        csp = app.config.get("CONTENT_SECURITY_POLICY")
        if csp:
            response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=()"
        return response


def register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db_command():
        """Create database tables with parameterized queries."""

        with app.app_context():
            db.create_all()
        click.echo("Database initialized.")

    @app.cli.command("create-admin")
    def create_admin():
        """Create an initial admin account via Flask CLI."""
        email = input("Admin email: ").strip().lower()
        full_name = input("Full name: ").strip()

        password_hash = _prompt_for_password()

        with app.app_context():
            secret = generate_totp_secret()
            admin = User(
                email=email,
                full_name=full_name,
                role="admin",
                password_hash=password_hash,
                totp_secret_encrypted=encrypt_totp_secret(secret),
            )
            db.session.add(admin)
            db.session.commit()
            provisioning_uri = f"otpauth://totp/Secure%20Pay:{email}?secret={secret}&issuer=Secure%20Pay"
            click.echo("Admin created successfully.")
            click.echo(f"TOTP secret: {secret}")
            click.echo("Add this secret to your authenticator app or use the URI below:")
            click.echo(provisioning_uri)
            logging.info("Admin created for %s", email)

    @click.command("delete-user")
    @click.option("--email", prompt=True, help="Email of the user to delete.")
    @click.option("--confirm", is_flag=True, help="Must be set to actually delete.")
    def delete_user_cmd(email, confirm):
        """Secure deletion of a user (admin or standard)."""
        from .models import User, Account, Transaction  # deferred import
        user = User.query.filter_by(email=email).first()
        if not user:
            click.echo("No such user.")
            return
        if not confirm:
            click.echo("Add --confirm to proceed with deletion.")
            return
        # Optional: archive transactions or leave them for audit (here we leave them).
        # We nullify foreign keys or keep historical integrity depending on schema.
        # If you want to freeze instead of delete: set user.is_active = False.
        # Ensure at least one admin remains:
        if user.role == "admin":
            remaining_admins = User.query.filter(User.role=="admin", User.id!=user.id).count()
            if remaining_admins == 0:
                click.echo("Refused: cannot delete the last remaining admin.")
                return
        # Delete accounts (or transfer balances to a system account before deleting)
        for acct in user.accounts:
            if acct.balance != 0:
                click.echo(f"Account {acct.account_number} has non-zero balance ({acct.balance}). Zero or transfer before deletion.")
                return
            db.session.delete(acct)
        db.session.delete(user)
        db.session.commit()
        click.echo(f"Deleted user {email}.")

    app.cli.add_command(init_db_command)
    app.cli.add_command(create_admin)
    app.cli.add_command(delete_user_cmd)
