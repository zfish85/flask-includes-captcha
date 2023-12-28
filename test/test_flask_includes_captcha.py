import string
import unittest
from hashlib import sha256
from unittest.mock import Mock, patch

from src.flask_includes_captcha import flask_includes_captcha


class TestFlaskCaptcha(unittest.TestCase):
    def setUp(self):
        self.app = Mock()
        self.app.config = {"CAPTCHA_KEY": "Secret_key"}
        self.captcha = flask_includes_captcha.FlaskCaptcha(self.app)

    def test_generate_text(self):
        text = flask_includes_captcha.generate_text()
        self.assertTrue(all(c in string.ascii_uppercase + string.digits for c in text))
        self.assertEqual(len(text), 4)

    def test_set_key(self):
        #
        result = flask_includes_captcha.set_key("")
        self.assertEqual(result, sha256(b"").digest())

        # Testfall 2: Überprüfe, ob die Funktion für einen nicht-leeren String funktioniert
        result = flask_includes_captcha.set_key("test123")
        self.assertEqual(result, sha256(b"test123").digest())

    @patch('src.flask_includes_captcha.flask_includes_captcha.ImageCaptcha.generate')
    @patch('src.flask_includes_captcha.flask_includes_captcha.base64.b64encode')
    def test_generate_captcha(self, base64_mock, captcha_mock):
        # Prepare mocks
        mock_data = captcha_mock.return_value
        mock_data.getvalue.return_value = b'Fake image'

        base64_mock.return_value = b'Fake image'

        # Test data

        text = "Text"

        # Function

        captcha = flask_includes_captcha.generate_captcha(text)

        # Check if mocks were called:

        captcha_mock.assert_called_once_with(text)
        base64_mock.assert_called_once_with(b'Fake image')

        # Check result

        expected_captcha = "Fake image"
        self.assertEqual(captcha, expected_captcha)

    @patch('src.flask_includes_captcha.flask_includes_captcha.generate_text')
    @patch('src.flask_includes_captcha.flask_includes_captcha.jwt.encode')
    @patch('src.flask_includes_captcha.flask_includes_captcha.generate_captcha')
    def test_create_captcha(self, mock_generate_captcha, mock_jwt_encode, mock_generate_text):
        # Prepare Mocks

        mock_generate_text.return_value = "TEXT"
        mock_jwt_encode.return_value = "ENCODED_TEXT"
        mock_generate_captcha.return_value = "CAPTURE_BYTES"

        result = self.captcha.create(4)

        # Check if Mocks called with correct parameters

        mock_generate_text.assert_called_once()
        mock_jwt_encode.assert_called_once_with({"text": "TEXT"}, self.captcha.key, algorithm="HS256")
        mock_generate_captcha.assert_called_once_with("TEXT")

        # Check result

        self.assertEqual(result, {'image': "CAPTURE_BYTES", 'token': "ENCODED_TEXT"})

    @patch('src.flask_includes_captcha.flask_includes_captcha.jwt.decode')
    def test_verify_captcha(self, mock_jwt_decode):
        # Test data
        text = "TEXT"

        # Prepare Mock

        mock_jwt_decode.return_value = {"text": text}

        # Call function

        result = self.captcha.verify(text, "hash_value")

        # Check if mock is called

        mock_jwt_decode.assert_called_once_with("hash_value", self.captcha.key, algorithms=["HS256"])

        # Check result

        self.assertTrue(result)

    @patch('src.flask_includes_captcha.flask_includes_captcha.jwt.decode',
           side_effect='src.flask_includes_captcha.flask_includes_captcha.jwt.DecodeError')
    def test_verify_captcha_invalid_token(self, mock_jwt_decode):
        # Prepare Mocks

        mock_jwt_decode.side_effect = flask_includes_captcha.jwt.DecodeError

        #  Call function

        result = self.captcha.verify("TEST", "invalid_token")

        # Check if mock is called

        mock_jwt_decode.assert_called_once_with("invalid_token", self.captcha.key, algorithms=["HS256"])

        # Check result

        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
