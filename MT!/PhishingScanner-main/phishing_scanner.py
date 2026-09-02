import argparse
import imaplib
import email
import re
import sys
import getpass
from email.message import EmailMessage
import language_tool_python
from bs4 import BeautifulSoup
from email_validator import validate_email, EmailNotValidError

# Connect to IMAP Server and start Inbox scanning
def connect_to_mailbox(server, username, password):
    try:
        mail = imaplib.IMAP4_SSL(server)
        mail.login(username, password)
        return mail
    except imaplib.IMAP4.error as e:
        print(f"IMAP authentication error: {str(e)}")
        return None
    except Exception as e:
        print(f"Connection error: {str(e)}")
        return None

# Validate email address
def validate_email_address(email_address):
    if not email_address:
        return False
    try:
        # Extract plain email address if formatted as 'Name <email@domain.com>'
        if "<" in email_address and ">" in email_address:
            match = re.search(r"<([^>]+)>", email_address)
            if match:
                email_address = match.group(1)
        validate_email(email_address, check_deliverability=False)
        return True
    except (EmailNotValidError, Exception):
        return False

# Extract URLs from text
def extract_urls(text):
    if not text:
        return []
    return re.findall(r"http[s]?://[^\s]+", text)

def is_malicious_url(url):
    # Known URL shorteners
    url_shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "cutt.ly"]

    # Check if the URL uses a shortener
    for shortener in url_shorteners:
        if shortener in url:
            return True

    # Check for known suspicious patterns
    suspicious_patterns = [
        r".*login.*",     # URLs with 'login' are potentially dangerous
        r".*password.*",  # URLs with 'password'
        r".*reset.*",     # URLs with 'reset'
        r".*verify.*",    # URLs with 'verify'
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    
    return False

# Get email body
def get_email_body(email_message):
    if not email_message:
        return ""
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        return payload.decode("utf-8")
                    except UnicodeDecodeError:
                        return payload.decode("latin-1")
            elif content_type == "text/html":
                html_content = part.get_payload(decode=True)
                if html_content:
                    try:
                        soup = BeautifulSoup(html_content, "html.parser")
                        return soup.get_text()
                    except Exception:
                        pass
    else:
        payload = email_message.get_payload(decode=True)
        if payload:
            try:
                return payload.decode("utf-8")
            except UnicodeDecodeError:
                return payload.decode("latin-1")
            except Exception:
                return str(payload)
        elif email_message.get_payload():
            return str(email_message.get_payload())
    return ""

# Check grammar in text
_lt_tool = None
_lt_checked = False

def check_grammar(text):
    global _lt_tool, _lt_checked
    if not text:
        return False
    if not _lt_checked:
        try:
            _lt_tool = language_tool_python.LanguageTool("en-US")
        except Exception:
            _lt_tool = None
        _lt_checked = True

    if _lt_tool is None:
        return False

    try:
        matches = _lt_tool.check(text)
        if len(matches) > 10:
            for match in matches:
                print(f"Grammar error at position {match.offset}: {match.message}")
            return True
        return False
    except Exception:
        return False

# Determine if an email is phishing
def is_phishing_email(email_message):
    try:
        sender = email_message.get("From", "")
        subject = email_message.get("Subject", "")
        body = get_email_body(email_message)

        if not validate_email_address(sender):
            print("Invalid email address: ", sender)
            return True 
        else:
            print("valid email address: ", sender)

        # Check for urgency keywords in subject
        urgency_keywords = ["urgent", "reset", "password", "account", "login", "update", "change", "renew", "verify", "confirm"]
        if any(keyword in subject.lower() for keyword in urgency_keywords):
            print("Urgency keyword in subject: ", subject)
            return True  # Suspicious if urgency-related keywords found
        
        # Check for common financial terms in subject
        financial_keywords = ["invoice", "payment", "credit card", "transfer", "bank", "fee", "refund", "billing", "transaction"]
        if any(keyword in subject.lower() for keyword in financial_keywords):
            print("Financial keyword in subject: ", subject)
            return True
        
        # Check for suspicious patterns in subject
        suspicious_patterns = [
            r"free .+",
            r"claim your .+",
            r"congratulations .+",
            r"you have won .+",
            r"exclusive offer",
            r"no reply",
            r"\d+% off"
        ]
        if any(re.search(pattern, subject, re.IGNORECASE) for pattern in suspicious_patterns):
            print("Suspicious pattern in subject: ", subject)
            return True
        
        # Check for suspicious keywords in body
        if re.search(r"\bpassword\b|\blogin\b|\baccount\b|\bverify\b|\bconfirm\b|\bupdate\b", body, re.IGNORECASE):
            print("Suspicious keywords in body.")
            return True
        
        # Check for suspicious URLs
        urls = extract_urls(body)
        for url in urls:
            if is_malicious_url(url):
                print(f"Malicious url found in email body: {url}")
                return True  # Found a malicious URL
            else:
                print("No Malicious url found in email body.")
        
        # Check for grammar errors
        if check_grammar(body):
            print("Grammar errors in email body.")
            return True
        else:
            print("No Grammer error found in email body.")

        return False

    except Exception as e:
        print("Error in determining phishing email: ", str(e))
        return True  # Assume phishing in case of unexpected error

# Scan for phishing emails in a given mailbox
def scan_emails(mail, mailbox="inbox"):
    try:
        mail.select(mailbox)
        result, data = mail.search(None, "UNSEEN")
        
        if result != "OK":
            raise Exception("Failed to retrieve email list")

        phishing_emails = []
        for num in data[0].split():
            result, data = mail.fetch(num, "(RFC822)")
            raw_email = data[0][1]
            email_message = email.message_from_bytes(raw_email)

            if is_phishing_email(email_message):
                phishing_emails.append(email_message)

        return phishing_emails
    
    except Exception as e:
        print(f"Error during email scan: {str(e)}")
        return []

def run_demo():
    print("=" * 60)
    print("Running Phishing Scanner Simulation / Demo")
    print("=" * 60)

    # Sample 1: Legitimate Email
    sample_safe = EmailMessage()
    sample_safe["From"] = "team@company.org"
    sample_safe["Subject"] = "Weekly Sprint Planning Meeting"
    sample_safe.set_content("Hi team, please find the agenda for our sync meeting at 10:00 AM.")

    # Sample 2: Phishing Email with Urgency and Malicious URL
    sample_phish = EmailMessage()
    sample_phish["From"] = "alert@security-service-update.com"
    sample_phish["Subject"] = "URGENT: Verify your account password immediately"
    sample_phish.set_content("Dear user, suspicious login detected. Reset your password here: http://bit.ly/secure-login-reset")

    print("\n--- Scanning Sample 1: Legitimate Email ---")
    is_phish1 = is_phishing_email(sample_safe)
    print(f"Result: {'[!] PHISHING DETECTED' if is_phish1 else '[OK] SAFE EMAIL'}")

    print("\n--- Scanning Sample 2: Suspicious Email ---")
    is_phish2 = is_phishing_email(sample_phish)
    print(f"Result: {'[!] PHISHING DETECTED' if is_phish2 else '[OK] SAFE EMAIL'}")
    print("=" * 60)

def main(args):
    if args.demo:
        run_demo()
        return

    # If required arguments are missing and not in demo mode
    if not (args.server and args.username and args.password):
        print("\nNo IMAP credentials provided. Running demo mode by default.\n(Pass --server, --username, and --password to scan a live mailbox).\n")
        run_demo()
        return

    mail = connect_to_mailbox(args.server, args.username, args.password)
    
    if not mail:
        print("Failed to connect to mailbox")
        return

    print(f"Connected to {args.server}. Scanning mailbox '{args.mailbox}' for unseen emails...")
    phishing_emails = scan_emails(mail, args.mailbox)

    if not phishing_emails:
        print("No phishing emails detected.")
    else:
        print(f"\nDetected {len(phishing_emails)} Phishing Email(s):")
        for email_message in phishing_emails:
            print("-" * 50)
            print("From: ", email_message["From"])
            print("Subject: ", email_message["Subject"])
            print("Body: ", get_email_body(email_message))
            print("-" * 50)

    try:
        mail.logout()
    except Exception:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phishing Email Scanner")
    parser.add_argument("--server", required=False, help="IMAP server address (e.g. imap.gmail.com)")
    parser.add_argument("--username", required=False, help="Email username/address")
    parser.add_argument("--password", required=False, help="Email password or App Password")
    parser.add_argument("--mailbox", default="inbox", help="Mailbox to scan (default: inbox)")
    parser.add_argument("--demo", action="store_true", help="Run a built-in simulation with test emails")
    
    args = parser.parse_args()
    main(args)