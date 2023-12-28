import base64
import json
import secrets
import string

from joserfc import jwe, errors
from captcha.image import ImageCaptcha
from hashlib import sha256


def generate_text(length=4):
    """
    Generate a random text of the specified length consisting of uppercase letters and digits.

    :param length: Length of the generated text (default is 4)
    :return: Randomly generated text
    """
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))


def generate_captcha(text):
    """
    Generate a captcha image based on the provided text.

    :param text: The text of the captcha image.
    :return: Base64-encoded representation of the captcha image.
    """

    image = ImageCaptcha()
    data = image.generate(text)
    return base64.b64encode(data.getvalue()).decode("utf-8")


def set_key(captcha_key):
    m = sha256()
    m.update(captcha_key.encode("utf-8"))
    return m.digest()


class FlaskCaptcha:
    """Flask extension class to create and verify captchas"""

    def __init__(self, app=None):
        self.key = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):

        self.key = set_key(app.config["CAPTCHA_KEY"])

    def create(self, length=4):
        """
        Create a captcha image and its corresponding token.

        :param length: Length of the captcha text to be generated (default is 4).
        :return: A dictionary containing the captcha image and its corresponding token.
        """
        text = generate_text(length)
        header = {"alg": "A256KW", "enc": "A256GCM"}
        token = jwe.encrypt_compact(header, json.dumps({"text": text}), self.key)
        return {"image": generate_captcha(text), "token": token}

    def verify(self, text, token):
        """
        Verify if the provided text matches the token.

        :param text: The text to be verified.
        :param token: The token to compare against.
        :return: True if the text matches the token, False otherwise.
        """

        try:
            plaintext_json = jwe.decrypt_compact(token, self.key).plaintext
            plaintext = json.loads(plaintext_json)["text"]
            return text == plaintext
        except errors.DecodeError:
            return False
