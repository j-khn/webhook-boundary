import unittest

from webhook_boundary import (
    ExpiredSignature,
    MalformedSignature,
    SignatureError,
    sign_for_example,
    verify_signature,
)


class WebhookSignatureTests(unittest.TestCase):
    def test_exact_raw_body_and_secret_rotation(self):
        body = b'{"amount":1,"currency":"EUR"}'
        header = sign_for_example(b"old-secret", body, 1_700_000_000)
        result = verify_signature(
            body, header, [b"new-secret", b"old-secret"],
            now=1_700_000_100, tolerance_seconds=300,
        )
        self.assertEqual(result.timestamp, 1_700_000_000)
        with self.assertRaises(SignatureError):
            verify_signature(
                b'{"currency":"EUR","amount":1}', header, [b"old-secret"],
                now=1_700_000_100,
            )

    def test_repeated_header_fields_are_supported(self):
        body = b"payload"
        header = sign_for_example(b"secret", body, 1000)
        timestamp, signature = header.split(",")
        result = verify_signature(body, [timestamp, signature], [b"secret"], now=1000)
        self.assertEqual(result.timestamp, 1000)

    def test_duplicate_timestamps_are_rejected(self):
        body = b"payload"
        header = sign_for_example(b"secret", body, 1000)
        with self.assertRaises(MalformedSignature):
            verify_signature(body, [header, "t=1000"], [b"secret"], now=1000)

    def test_stale_signature_is_rejected(self):
        body = b"payload"
        header = sign_for_example(b"secret", body, 1000)
        with self.assertRaises(ExpiredSignature):
            verify_signature(body, header, [b"secret"], now=1401)

    def test_invalid_digest_is_rejected(self):
        with self.assertRaises(MalformedSignature):
            verify_signature(b"payload", "t=1000,v1=not-a-digest", [b"secret"], now=1000)


if __name__ == "__main__":
    unittest.main()
