import re

SOURCE_TERM_RE = re.compile(
    r'(?<![A-Za-z0-9/\-._])'
    r'([A-Za-z][A-Za-z0-9/\-._]*|[0-9]+[A-Za-z][A-Za-z0-9/\-._]*)'
    r'(?![A-Za-z0-9/\-._])'
)
PLACEHOLDER_RE = re.compile(r'__TERM_(\d+)__', re.IGNORECASE)

SOURCE_TERM_STOPWORDS = frozenset({
    'a', 'an', 'and', 'are', 'as', 'at', 'be', 'been', 'but', 'by',
    'can', 'could', 'did', 'do', 'does', 'for', 'from', 'had', 'has',
    'have', 'in', 'is', 'it', 'may', 'might', 'no', 'not', 'of', 'only',
    'or', 'that', 'the', 'this', 'to', 'was', 'were', 'will', 'with',
})

# Acronyms that are legitimate to localize; the glossary decides the allowed
# targets. Keep this explicit rather than treating them as English stopwords.
PROTECT_EXCEPTIONS = frozenset({'AI'})


def extract_source_terms(text):
    return [match.group(1) for match in SOURCE_TERM_RE.finditer(text)
            if match.group(1) not in SOURCE_TERM_STOPWORDS]


def protect_terms(text):
    protected = []

    def replace(match):
        term = match.group(1)
        if term in SOURCE_TERM_STOPWORDS or term in PROTECT_EXCEPTIONS:
            return match.group(0)
        protected.append(term)
        return f"__TERM_{len(protected) - 1}__"

    return SOURCE_TERM_RE.sub(replace, text), protected


def restore_placeholders(text, protected):
    def replace(match):
        index = int(match.group(1))
        if index < len(protected):
            return protected[index]
        return match.group(0)

    return PLACEHOLDER_RE.sub(replace, text)
