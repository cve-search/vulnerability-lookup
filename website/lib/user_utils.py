import qrcode  # type: ignore[import-untyped]
from io import BytesIO
from typing import Any
from typing import Union
from base64 import b64encode
from itsdangerous import URLSafeTimedSerializer

from website.web.bootstrap import application


def generate_confirmation_token(login: str) -> str:
    """Generates a time-based token. Used for the account activation."""
    serializer = URLSafeTimedSerializer(application.config["SECRET_KEY"])
    return serializer.dumps(login, salt=application.config["SECURITY_PASSWORD_SALT"])


def confirm_token(token: str) -> Union[bool, Any]:
    """Confirm a time-based token and ensures that the signature is not older
    than that TOKEN_VALIDITY_PERIOD in seconds."""
    serializer = URLSafeTimedSerializer(application.config["SECRET_KEY"])
    try:
        login = serializer.loads(
            token,
            salt=application.config["SECURITY_PASSWORD_SALT"],
            max_age=application.config["TOKEN_VALIDITY_PERIOD"],
        )
    except Exception:
        return False
    return login


def get_b64encoded_qr_image(data: str) -> str:
    """Returns a QRCode generated with the provided data."""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered)
    return b64encode(buffered.getvalue()).decode("utf-8")
