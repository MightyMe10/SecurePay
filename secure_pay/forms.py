"""WTForms definitions with built-in CSRF protection."""
from __future__ import annotations

from decimal import Decimal

from flask_wtf import FlaskForm
from wtforms import BooleanField, DecimalField, HiddenField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Regexp

ACCOUNT_REGEX = r"^[0-9]{6,18}$"


class RegistrationForm(FlaskForm):
    full_name = StringField("Full Name", validators=[DataRequired(), Length(max=120)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=12, max=128),
            Regexp(r".*[A-Z].*", message="Include at least one uppercase letter."),
            Regexp(r".*[a-z].*", message="Include at least one lowercase letter."),
            Regexp(r".*\d.*", message="Include at least one digit."),
            Regexp(r".*[^A-Za-z0-9].*", message="Include at least one special character."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")],
    )
    submit = SubmitField("Create Account")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    totp_code = StringField(
        "Authenticator Code",
        validators=[DataRequired(), Length(min=6, max=6), Regexp(r"^\d{6}$", message="Enter the 6-digit code.")],
    )
    submit = SubmitField("Sign In")


class TransferForm(FlaskForm):
    target_account = StringField(
        "Recipient Account",
        validators=[DataRequired(), Regexp(ACCOUNT_REGEX, message="Account must be numeric."), Length(min=6, max=18)],
    )
    amount = DecimalField(
        "Amount",
        places=2,
        rounding=None,
        validators=[DataRequired(), NumberRange(min=Decimal("0.01"), message="Amount must be positive.")],
    )
    description = TextAreaField("Description", validators=[Length(max=255)])
    submit = SubmitField("Transfer Funds")


class BeneficiaryForm(FlaskForm):
    nickname = StringField("Nickname", validators=[DataRequired(), Length(max=120)])
    account_number = StringField(
        "Account Number",
        validators=[DataRequired(), Regexp(ACCOUNT_REGEX, message="Account must be numeric."), Length(min=6, max=18)],
    )
    submit = SubmitField("Save Beneficiary")


class BeneficiaryDeleteForm(FlaskForm):
    beneficiary_id = HiddenField(validators=[DataRequired()])
    submit = SubmitField("Remove")


class SessionTerminateForm(FlaskForm):
    session_id = HiddenField(validators=[DataRequired()])
    submit = SubmitField("Log Out Device")


class AdminFreezeForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired()])
    submit = SubmitField("Toggle Status")


class AdminResetPasswordForm(FlaskForm):
    user_id = HiddenField(validators=[DataRequired()])
    submit = SubmitField("Reset Password")


class PasswordResetForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField(
        "New Password",
        validators=[
            DataRequired(),
            Length(min=12, max=128),
            Regexp(r".*[A-Z].*", message="Include at least one uppercase letter."),
            Regexp(r".*[a-z].*", message="Include at least one lowercase letter."),
            Regexp(r".*\d.*", message="Include at least one digit."),
            Regexp(r".*[^A-Za-z0-9].*", message="Include at least one special character."),
        ],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords must match.")],
    )
    totp_code = StringField(
        "Authenticator Code",
        validators=[DataRequired(), Length(min=6, max=6), Regexp(r"^\d{6}$", message="Enter the 6-digit code.")],
    )
    submit = SubmitField("Update Password")
