import base64
import secrets
import string

import jwt
from captcha.image import ImageCaptcha


def generate_text(length=4):
    """
    Generate a random text of the specified length consisting of uppercase letters and digits.

    :param length: Length of the generated text (default is 4)
    :return: Randomly generated text
    """
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for i in range(length))


def generate_captcha(text):
    """
    Generate a captcha image based on the provided text.

    :param text: The text of the captcha image.
    :return: Base64-encoded representation of the captcha image.
    """

    image = ImageCaptcha()
    data = image.generate(text)
    return base64.b64encode(data.getvalue()).decode("utf-8")


class FlaskCaptcha:
    """Flask extension class to create and verify captchas"""
    def __init__(self, app=None):
        self.key = None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):

        self.key = app.config["CAPTCHA_KEY"]

    def create(self, length=4):
        """
        Create a captcha image and its corresponding hash value.

        :param length: Length of the captcha text to be generated (default is 4).
        :return: A dictionary containing the captcha image and its hash value.
        """
        text = generate_text(length)
        hash_value = jwt.encode({"text": text}, self.key, algorithm="HS256")
        return {"image": generate_captcha(text), "hash": hash_value}

    def verify(self, text, hash_value):
        """
        Verify if the provided text matches the hash value.

        :param text: The text to be verified.
        :param hash_value: The hash value to compare against.
        :return: True if the text matches the hash value, False otherwise.
        """
        try:
            return text == jwt.decode(hash_value, self.key, algorithms=["HS256"])["text"]
        except jwt.DecodeError:
            return False
