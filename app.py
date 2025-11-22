"""Secure Pay application entrypoint."""
import os

from secure_pay import create_app

app = create_app(os.getenv("FLASK_ENV", "development"))


if __name__ == "__main__":
    app.run()
