import argparse
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from securemail import client


class RegisterTest(unittest.TestCase):
    def test_failed_register_does_not_create_identity_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(
                username="henrique.de.almeida",
                domain="securemail.local",
                server="http://127.0.0.1:8471",
            )
            with mock.patch.object(client, "IDENTITY_DIR", Path(tmp)):
                with mock.patch.object(client, "_request", return_value={"registered": False}):
                    with mock.patch.object(client, "_lookup_keys", return_value=None):
                        code = client.cmd_register(args)
            self.assertEqual(code, 1)
            self.assertEqual(list(Path(tmp).glob("*.json")), [])


class EnsureIdentityTest(unittest.TestCase):
    def test_missing_identity_is_generated_and_saved(self):
        username = "henrique.de.almeida@securemail.local"
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(client, "IDENTITY_DIR", Path(tmp)):
                path = client._identity_path(username)
                with mock.patch.object(client, "_lookup_keys", return_value=None):
                    with mock.patch.object(client, "_request", return_value={"registered": True}):
                        identity = client._ensure_private_identity(
                            "http://127.0.0.1:8471",
                            username,
                            "securemail.local",
                        )
            self.assertTrue(path.exists())
            self.assertEqual(
                identity.public_signing_b64(),
                client.Identity.load(str(path)).public_signing_b64(),
            )

    def test_missing_local_private_key_is_rejected_if_server_knows_address(self):
        username = "henrique.de.almeida@securemail.local"
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(client, "IDENTITY_DIR", Path(tmp)):
                with mock.patch.object(
                    client,
                    "_lookup_keys",
                    return_value={"signing_pub": "sig", "encryption_pub": "enc"},
                ):
                    with self.assertRaises(SystemExit):
                        client._ensure_private_identity(
                            "http://127.0.0.1:8471",
                            username,
                            "securemail.local",
                        )


class MailboxRenderTest(unittest.TestCase):
    def test_mailbox_page_escapes_content(self):
        page = client._render_mailbox_page(
            "henrique.de.almeida@securemail.local",
            [
                {
                    "id": 7,
                    "received_at": 1_726_000_000,
                    "sender": "<script>@example.com",
                    "message": "bonjour\n<b>privé</b>",
                    "ok": True,
                }
            ],
            "<ok>",
        )
        self.assertIn("Boîte privée de henrique.de.almeida@securemail.local", page)
        self.assertIn("&lt;script&gt;@example.com", page)
        self.assertIn("bonjour<br>&lt;b&gt;privé&lt;/b&gt;", page)
        self.assertIn("&lt;ok&gt;", page)
        self.assertIn("Supprimer les messages cochés", page)


if __name__ == "__main__":
    unittest.main()
