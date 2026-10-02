"""Email analysis and detection package."""
from detection.email.parser import parse_email, ParsedEmail
from detection.email.heuristics import analyze_email_heuristics

__all__ = ["parse_email", "ParsedEmail", "analyze_email_heuristics"]
