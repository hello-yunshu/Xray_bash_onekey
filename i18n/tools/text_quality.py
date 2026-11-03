"""Text metrics shared by glossary checks and the README quality gate."""

import re
from collections import Counter
from difflib import SequenceMatcher

FENCE_RE = re.compile(r'^\s*(```|~~~)')
INLINE_CODE_RE = re.compile(r'`([^`\n]+)`')
LINK_TARGET_RE = re.compile(r'\]\(([^)]+)\)')
IMAGE_RE = re.compile(r'!\[[^\]]*\]\(([^)]+)\)')
COMMENT_RE = re.compile(r'<!--.*?-->', re.S)
RAW_URL_RE = re.compile(r'https?://\S+')
HEADING_RE = re.compile(r'^\s{0,3}(#{1,6})\s+\S', re.M)
CHINESE_RE = re.compile(r'[\u4e00-\u9fff]')
CJK_PUNCT_RE = re.compile(r'[，。：；、！？（）【】《》「」『』]')
PLACEHOLDER_RE = re.compile(
    r'(\{\{[^{}]+\}\}|\$\{[^{}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|'
    r'%[0-9]+\$[sd]|%[sd]|__TERM_[0-9]+__)'
)

PUNCT_MAP = {
    '，': ',', '。': '.', '：': ':', '；': ';', '、': ',',
    '！': '!', '？': '?', '（': '(', '）': ')',
    '【': '[', '】': ']', '《': '"', '》': '"',
    '「': '"', '」': '"', '『': "'", '』': "'",
}


def _outside_fences(text):
    lines = []
    in_fence = False
    for line in text.splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    return '\n'.join(lines)


def _strip_protected(value, keep_inline_code):
    value = IMAGE_RE.sub('', value)
    value = COMMENT_RE.sub('', value)
    value = RAW_URL_RE.sub('', value)
    value = LINK_TARGET_RE.sub(']', value)
    if not keep_inline_code:
        value = INLINE_CODE_RE.sub('', value)
    return value


def visible_text(text):
    """Prose only: no fenced code, inline code, URLs, images or comments."""
    return _strip_protected(_outside_fences(text), keep_inline_code=False)


def residue_text(text, include_inline_code=True):
    """Prose plus (optionally) inline code; fenced code stays excluded."""
    return _strip_protected(_outside_fences(text), keep_inline_code=include_inline_code)


def fenced_content(text):
    lines = []
    in_fence = False
    for line in text.splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            lines.append(line)
    return '\n'.join(lines)


def chinese_chars(text, include_inline_code=True):
    return CHINESE_RE.findall(residue_text(text, include_inline_code=include_inline_code))


def chinese_punctuation(text, include_inline_code=True):
    return CJK_PUNCT_RE.findall(residue_text(text, include_inline_code=include_inline_code))


def chinese_in_code_blocks(text):
    return CHINESE_RE.findall(fenced_content(text))


def normalize_punctuation(text):
    for source, target in PUNCT_MAP.items():
        text = text.replace(source, target)
    text = re.sub(r'\.{2,}', '.', text)
    text = re.sub(r',{2,}', ',', text)
    return text


def placeholders(text):
    return sorted(PLACEHOLDER_RE.findall(text))


def paragraph_count(text):
    blocks = [b for b in re.split(r'\n\s*\n', visible_text(text)) if b.strip()]
    return len(blocks)


def heading_levels(text):
    counts = Counter()
    for match in HEADING_RE.finditer(_outside_fences(text)):
        counts[len(match.group(1))] += 1
    return dict(counts)


def visible_chars(text):
    return len(re.sub(r'\s+', '', visible_text(text)))


def length_ratio(source_text, translated_text):
    source = visible_chars(source_text)
    target = visible_chars(translated_text)
    return (target / source) if source else 1.0


def _normalized_zh(text):
    return re.sub(r'[^\u4e00-\u9fff0-9A-Za-z]+', '', text).lower()


def similarity(source_text, back_translated_text):
    source = _normalized_zh(source_text)
    back = _normalized_zh(back_translated_text)
    if not source or not back:
        return 0.0
    sequence = SequenceMatcher(None, source, back).ratio()
    if len(source) >= 2 and len(back) >= 2:
        source_bigrams = {source[i:i + 2] for i in range(len(source) - 1)}
        back_bigrams = {back[i:i + 2] for i in range(len(back) - 1)}
        jaccard = len(source_bigrams & back_bigrams) / len(source_bigrams | back_bigrams)
    else:
        jaccard = sequence
    return max(sequence, jaccard)


def contains_term(text, term, case_sensitive=False):
    if re.search(r'[A-Za-z0-9]', term):
        pattern = f'(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])'
        flags = 0 if case_sensitive else re.IGNORECASE
        return bool(re.search(pattern, text, flags))
    return term in text
