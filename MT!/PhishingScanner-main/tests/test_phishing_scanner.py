import unittest
from unittest.mock import MagicMock, patch
from email.message import EmailMessage
from phishing_scanner import (
    connect_to_mailbox,
    validate_email_address,
    get_email_body,
    extract_urls,
    check_grammar,
    is_malicious_url,
    is_phishing_email,
    scan_emails,
)

class TestPhishingScanner(unittest.TestCase):
    def setUp(self):
        # Prepare common test data
        self.valid_email = "valid@example.com"
        self.invalid_email = "invalid-email"

        # Create a basic email message with text content
        self.email_message = EmailMessage()
        self.email_message["From"] = self.valid_email
        self.email_message["Subject"] = "Test Subject"
        self.email_message.set_content("This is a test email body.")

        # Create a multipart email with HTML content
        self.multipart_email = EmailMessage()
        self.multipart_email.add_alternative(
            "<html><body>This is an HTML email body.</body></html>", subtype="html"
        )

    @patch("imaplib.IMAP4_SSL")
    def test_connect_to_mailbox(self, mock_imap_ssl):
        # Mock IMAP connection
        mock_instance = MagicMock()
        mock_imap_ssl.return_value = mock_instance
        mock_instance.login.return_value = ("OK", [b"LOGIN completed"])

        mail = connect_to_mailbox("imap.example.com", "user", "password")
        self.assertIsNotNone(mail)
        mock_instance.login.assert_called_once_with("user", "password")

    def test_validate_email_address(self):
        # Test with valid email
        self.assertTrue(validate_email_address(self.valid_email))
        self.assertTrue(validate_email_address("John Doe <john@example.com>"))

        # Test with invalid email
        self.assertFalse(validate_email_address(self.invalid_email))
        self.assertFalse(validate_email_address(""))

    def test_get_email_body(self):
        # Test with plain text email
        body = get_email_body(self.email_message)
        self.assertEqual(body.strip(), "This is a test email body.")

        # Test with multipart HTML email
        body_html = get_email_body(self.multipart_email).strip()
        self.assertEqual(body_html, "This is an HTML email body.")

    def test_extract_urls(self):
        # Test with text containing URLs
        text_with_urls = "Visit http://example.com and https://example.org for more info."
        urls = extract_urls(text_with_urls)
        self.assertEqual(len(urls), 2)
        self.assertIn("http://example.com", urls)
        self.assertIn("https://example.org", urls)

    def test_is_malicious_url(self):
        # Test with known URL shorteners
        self.assertTrue(is_malicious_url("http://bit.ly/12345"))
        self.assertTrue(is_malicious_url("https://tinyurl.com/abc"))
        self.assertTrue(is_malicious_url("https://example.com/login-reset-verify"))

        # Test with safe URL
        self.assertFalse(is_malicious_url("https://example.com/about-us"))

    def test_check_grammar(self):
        with patch("phishing_scanner._lt_tool") as mock_lt:
            # Mock high error count (> 10 errors)
            mock_match = MagicMock()
            mock_match.offset = 0
            mock_match.message = "Error"
            mock_lt.check.return_value = [mock_match] * 12

            with patch("phishing_scanner._lt_checked", True):
                self.assertTrue(check_grammar("Any text with many errors"))

            # Mock low error count (<= 10 errors)
            mock_lt.check.return_value = []
            with patch("phishing_scanner._lt_checked", True):
                self.assertFalse(check_grammar("Clean text"))

    def test_is_phishing_email(self):
        # Test a non-phishing email
        self.assertFalse(is_phishing_email(self.email_message))

        # Test a phishing email with suspicious subject
        phishing_email = EmailMessage()
        phishing_email["From"] = self.valid_email
        phishing_email["Subject"] = "URGENT: Reset your password"
        phishing_email.set_content("Please reset your password.")
        self.assertTrue(is_phishing_email(phishing_email))

        # Test a phishing email with malicious URL
        phishing_email_url = EmailMessage()
        phishing_email_url["From"] = self.valid_email
        phishing_email_url["Subject"] = "Check this link"
        phishing_email_url.set_content("Check this link: http://bit.ly/12345")
        self.assertTrue(is_phishing_email(phishing_email_url))

    def test_scan_emails(self):
        mock_mail = MagicMock()
        mock_mail.select.return_value = ("OK", [b"1"])
        mock_mail.search.return_value = ("OK", [b"1"])

        raw_email = (
            b"From: safe@example.com\r\n"
            b"Subject: Meeting Notes\r\n\r\n"
            b"Notes from today meeting."
        )
        mock_mail.fetch.return_value = ("OK", [(b"1 (RFC822 {100})", raw_email)])

        phishing_emails = scan_emails(mock_mail, mailbox="inbox")
        self.assertIsInstance(phishing_emails, list)
        self.assertEqual(len(phishing_emails), 0)

if __name__ == "__main__":
    unittest.main()

