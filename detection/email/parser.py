"""Safe email parsing and URL extraction."""
import re
import email
from email import policy
from email.parser import BytesParser, Parser
from dataclasses import dataclass, field
from typing import List, Dict, Any, Union, Optional
from html.parser import HTMLParser


URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))"""
)


class SimpleHTMLTextExtractor(HTMLParser):
    """Safe HTML parser to extract visible text and href URLs without external deps."""
    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for name, val in attrs:
                if name.lower() == "href" and val:
                    self.hrefs.append(val.strip())

    def handle_data(self, data):
        if data.strip():
            self.text_parts.append(data.strip())

    def get_text(self) -> str:
        return " ".join(self.text_parts)


@dataclass
class ParsedEmail:
    sender: str = ""
    sender_name: str = ""
    sender_domain: str = ""
    recipient: str = ""
    subject: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    plain_body: str = ""
    extracted_urls: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    has_html: bool = False
    is_valid: bool = True
    error_message: Optional[str] = None


def extract_domain_from_email(addr: str) -> str:
    """Extract domain part from email address string."""
    if "@" in addr:
        return addr.split("@")[-1].strip().lower().rstrip(">")
    return ""


def extract_urls_from_text(text: str) -> List[str]:
    """Extract and deduplicate HTTP/HTTPS URLs from plain text or HTML."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    urls = []
    for m in matches:
        u = m[0]
        if not u.startswith("http://") and not u.startswith("https://"):
            u = "http://" + u
        if u not in urls:
            urls.append(u)
    return urls[:25]  # Limit URL count to prevent DoS


def parse_email(raw_input: Union[str, Dict[str, Any]], max_body_len: int = 20000) -> ParsedEmail:
    """
    Parse an email from either a JSON dict {sender, subject, body}
    or a raw RFC 822 / MIME string.
    """
    if isinstance(raw_input, dict):
        sender = str(raw_input.get("sender", "")).strip()
        subject = str(raw_input.get("subject", "")).strip()
        body = str(raw_input.get("body", "")).strip()[:max_body_len]

        # Extract display name vs email if formatted like "Name <email@domain>"
        name_match = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>$', sender)
        if name_match:
            sender_name = name_match.group(1).strip()
            sender_addr = name_match.group(2).strip()
        else:
            sender_name = ""
            sender_addr = sender

        sender_domain = extract_domain_from_email(sender_addr)

        # Extract URLs
        html_extractor = SimpleHTMLTextExtractor()
        try:
            html_extractor.feed(body)
            all_urls = list(set(html_extractor.hrefs + extract_urls_from_text(body)))
        except Exception:
            all_urls = extract_urls_from_text(body)

        return ParsedEmail(
            sender=sender_addr,
            sender_name=sender_name,
            sender_domain=sender_domain,
            subject=subject,
            plain_body=body,
            extracted_urls=all_urls[:25],
            is_valid=bool(sender or subject or body),
        )

    # Otherwise parse as raw RFC 822 string
    raw_str = str(raw_input).strip()
    if not raw_str:
        return ParsedEmail(is_valid=False, error_message="Empty raw email input")

    try:
        msg = Parser(policy=policy.default).parsestr(raw_str)
        sender_header = str(msg.get("From", "")).strip()
        subject = str(msg.get("Subject", "")).strip()
        recipient = str(msg.get("To", "")).strip()
        reply_to_header = str(msg.get("Reply-To", "")).strip()

        # Sender address extraction
        name_match = re.match(r'^"?([^"<]*)"?\s*<([^>]+)>$', sender_header)
        if name_match:
            sender_name = name_match.group(1).strip()
            sender_addr = name_match.group(2).strip()
        else:
            sender_name = ""
            sender_addr = sender_header

        sender_domain = extract_domain_from_email(sender_addr)
        reply_to_domain = extract_domain_from_email(reply_to_header)

        # Extract body
        body_parts = []
        has_html = False
        html_urls = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition", ""))
                if "attachment" in cdispo:
                    continue
                if ctype == "text/plain":
                    try:
                        body_parts.append(part.get_content())
                    except Exception:
                        pass
                elif ctype == "text/html":
                    has_html = True
                    try:
                        html_content = part.get_content()
                        extractor = SimpleHTMLTextExtractor()
                        extractor.feed(html_content)
                        body_parts.append(extractor.get_text())
                        html_urls.extend(extractor.hrefs)
                    except Exception:
                        pass
        else:
            ctype = msg.get_content_type()
            try:
                content = msg.get_content()
                if ctype == "text/html":
                    has_html = True
                    extractor = SimpleHTMLTextExtractor()
                    extractor.feed(content)
                    body_parts.append(extractor.get_text())
                    html_urls.extend(extractor.hrefs)
                else:
                    body_parts.append(content)
            except Exception:
                body_parts.append(msg.get_payload() or "")

        full_body = "\n".join(body_parts)[:max_body_len]
        all_urls = list(dict.fromkeys(html_urls + extract_urls_from_text(full_body)))[:25]

        headers_dict = {
            "from": sender_header,
            "to": recipient,
            "subject": subject,
            "reply-to": reply_to_header,
            "received-spf": str(msg.get("Received-SPF", "")),
            "authentication-results": str(msg.get("Authentication-Results", "")),
        }

        return ParsedEmail(
            sender=sender_addr,
            sender_name=sender_name,
            sender_domain=sender_domain,
            recipient=recipient,
            subject=subject,
            reply_to=reply_to_header,
            reply_to_domain=reply_to_domain,
            plain_body=full_body,
            extracted_urls=all_urls,
            headers=headers_dict,
            has_html=has_html,
            is_valid=True,
        )

    except Exception as exc:
        return ParsedEmail(
            is_valid=False,
            error_message=f"Failed to parse raw RFC 822 email: {str(exc)}",
        )
