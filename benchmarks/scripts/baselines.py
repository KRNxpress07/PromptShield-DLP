"""Small standalone baseline; intentionally no project pattern imports."""
import re

# Obvious email/phone/card/IP and legacy key shapes. No NER, context validation,
# checksum, JWT decoding, sophisticated overlaps, or custom post-processing.
PATTERNS = {
    'EMAIL_ADDRESS': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    'PHONE_NUMBER': r'\+\d[\d ()-]{8,18}\d',
    'CREDIT_CARD': r'\b(?:\d[ -]?){15}\d\b',
    'IP_ADDRESS': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'US_SSN': r'\b\d{3}-\d{2}-\d{4}\b',
    'API_KEY': r'\bsk-[A-Za-z0-9]{20,}\b',
    'AWS_ACCESS_KEY': r'\bAKIA[A-Z0-9]{16}\b',
}


def simple_regex(text):
    return [{'entity_type': entity, 'start': m.start(), 'end': m.end(), 'score': 1.0}
            for entity, pattern in PATTERNS.items() for m in re.finditer(pattern, text)]
