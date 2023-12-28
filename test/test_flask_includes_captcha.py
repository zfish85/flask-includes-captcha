import json
import string
import unittest
from hashlib import sha256
from unittest.mock import Mock, patch

import joserfc

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
    @patch('src.flask_includes_captcha.flask_includes_captcha.jwe.encrypt_compact')
    @patch('src.flask_includes_captcha.flask_includes_captcha.generate_captcha')
    def test_create_captcha(self, mock_generate_captcha, mock_jwe_encrypt_compact, mock_generate_text):
        # Prepare Mocks

        mock_generate_text.return_value = "TEXT"
        mock_jwe_encrypt_compact.return_value = "ENCODED_TEXT"
        mock_generate_captcha.return_value = "CAPTURE_BYTES"

        result = self.captcha.create(4)

        # Check if Mocks called with correct parameters

        mock_generate_text.assert_called_once()
        mock_jwe_encrypt_compact.assert_called_once_with({"alg": "A256KW", "enc": "A256GCM"},
                                                         '{"text": "TEXT"}', self.captcha.key)
        mock_generate_captcha.assert_called_once_with("TEXT")

        # Check result

        self.assertEqual(result, {'image': "CAPTURE_BYTES", 'token': "ENCODED_TEXT"})

    @patch('src.flask_includes_captcha.flask_includes_captcha.jwe.decrypt_compact')
    def test_verify_captcha(self, mock_jwe_decrypt_compact):
        # Test data
        text = "TEXT"

        # Prepare Mock

        mock_jwe_decrypt_compact.return_value.plaintext = json.dumps({"text": text})

        # Call function

        result = self.captcha.verify(text, "hash_value")

        # Check if mock is called

        mock_jwe_decrypt_compact.assert_called_once_with("hash_value", self.captcha.key)

        # Check result

        self.assertTrue(result)

    @patch('src.flask_includes_captcha.flask_includes_captcha.jwe.decrypt_compact',
           side_effect='src.flask_includes_captcha.flask_includes_captcha.joserfc.errors.DecodeError')
    def test_verify_captcha_invalid_token(self, mock_jwe_decrypt_compact):
        # Prepare Mocks

        mock_jwe_decrypt_compact.side_effect = joserfc.errors.DecodeError

        #  Call function

        result = self.captcha.verify("TEST", "invalid_token")

        # Check if mock is called

        mock_jwe_decrypt_compact.assert_called_once_with("invalid_token", self.captcha.key)

        # Check result

        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
