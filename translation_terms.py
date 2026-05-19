import re

SOURCE_TERM_RE = re.compile(
    r'(?<![A-Za-z0-9/\-._])'
    r'([A-Za-z][A-Za-z0-9/\-._]*|[0-9]+[A-Za-z][A-Za-z0-9/\-._]*)'
    r'(?![A-Za-z0-9/\-._])'
)
PLACEHOLDER_RE = re.compile(r'__TERM_(\d+)__', re.IGNORECASE)


def extract_source_terms(text):
    return [match.group(1) for match in SOURCE_TERM_RE.finditer(text)]


def protect_terms(text):
    protected = []

    def replace(match):
        protected.append(match.group(1))
        return f"__TERM_{len(protected) - 1}__"

    return SOURCE_TERM_RE.sub(replace, text), protected


def restore_placeholders(text, protected):
    def replace(match):
        index = int(match.group(1))
        if index < len(protected):
            return protected[index]
        return match.group(0)

    return PLACEHOLDER_RE.sub(replace, text)


def _term_present(text, term):
    pattern = r'(?<![A-Za-z0-9/\-._])' + re.escape(term) + r'(?![A-Za-z0-9/\-._])'
    return re.search(pattern, text) is not None


def _camel_words(term):
    words = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', term)
    return words if words != term else ""


def restore_source_terms(translated, source):
    for term in sorted(set(extract_source_terms(source)), key=len, reverse=True):
        pattern = r'(?<![A-Za-z0-9/\-._])' + re.escape(term) + r'(?![A-Za-z0-9/\-._])'
        if re.search(pattern, translated, flags=re.IGNORECASE):
            translated = re.sub(pattern, term, translated, flags=re.IGNORECASE)
            continue

        spaced = _camel_words(term)
        if spaced:
            spaced_pattern = r'(?<![A-Za-z0-9/\-._])' + re.escape(spaced) + r'(?![A-Za-z0-9/\-._])'
            translated = re.sub(spaced_pattern, term, translated, flags=re.IGNORECASE)
            continue

        for part in re.split(r'[/\-._]', term):
            if len(part) > 1:
                part_pattern = r'(?<![A-Za-z0-9])' + re.escape(part) + r'(?![A-Za-z0-9])'
                translated = re.sub(part_pattern, part, translated, flags=re.IGNORECASE)
    return translated


def missing_source_terms(translated, source):
    restored = restore_source_terms(translated, source)
    missing = []
    for term in extract_source_terms(source):
        if term not in missing and not _term_present(restored, term):
            missing.append(term)
    return missing


def ensure_source_terms(translated, source):
    restored = restore_source_terms(translated, source)
    missing = missing_source_terms(restored, source)
    if missing:
        restored = f"{restored} [{' / '.join(missing)}]"
    return restored
