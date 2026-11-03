"""Structural validation for generated README translations."""

import os
import re

LANGUAGES = ("en", "fr", "ru", "fa", "ko")
CHINESE_RE = re.compile(r'[\u4e00-\u9fff]')
FENCE_LINE_RE = re.compile(r'^\s*(```|~~~)')
INLINE_CODE_RE = re.compile(r'`([^`\n]+)`')
URL_RE = re.compile(r'\]\(([^)]+)\)')
IMAGE_RE = re.compile(r'!\[[^\]]*\]\(([^)]+)\)')
COMMENT_RE = re.compile(r'<!--.*?-->', re.S)
HEADING_RE = re.compile(r'^\s{0,3}#{1,6}\s+', re.M)
TABLE_SEP_RE = re.compile(r'^\s*\|?[\s:.-]+\|[\s|:.-]*$', re.M)
RAW_URL_RE = re.compile(r'https?://\S+')
VERSION_RE = re.compile(r'当前版本：\*\*([0-9]+(?:\.[0-9]+)+)\*\*')


def _read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def _fences(text):
    return [line.strip() for line in text.splitlines() if FENCE_LINE_RE.match(line)]


def _inline_code(text):
    return sorted(INLINE_CODE_RE.findall(text))


def _urls(text):
    return sorted(URL_RE.findall(text))


def _images(text):
    return sorted(IMAGE_RE.findall(text))


def _comments(text):
    return sorted(COMMENT_RE.findall(text))


def _headings(text):
    return len(HEADING_RE.findall(text))


def _table_separators(text):
    return len(TABLE_SEP_RE.findall(text))


def _visible_text(text):
    """Remove content that must stay byte-for-byte untranslated or invisible."""
    lines = []
    in_fence = False
    for line in text.splitlines():
        if FENCE_LINE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    value = "\n".join(lines)
    value = INLINE_CODE_RE.sub('', value)
    value = IMAGE_RE.sub('', value)
    value = COMMENT_RE.sub('', value)
    value = RAW_URL_RE.sub('', value)
    value = URL_RE.sub(']', value)
    return value


def validate_pair(source_text, translated_text):
    errors = []
    if not translated_text.strip():
        return ["empty output"]

    if _fences(translated_text) != _fences(source_text):
        errors.append(
            f"fenced code blocks differ ({len(_fences(translated_text))} vs {len(_fences(source_text))})"
        )
    if _inline_code(translated_text) != _inline_code(source_text):
        errors.append("inline code spans differ")
    if _urls(translated_text) != _urls(source_text):
        errors.append("link URLs differ")
    if _images(translated_text) != _images(source_text):
        errors.append("image paths differ")
    if _comments(translated_text) != _comments(source_text):
        errors.append("HTML comments differ")
    if _headings(translated_text) != _headings(source_text):
        errors.append(
            f"heading count differs ({_headings(translated_text)} vs {_headings(source_text)})"
        )
    if _table_separators(translated_text) != _table_separators(source_text):
        errors.append(
            f"table separator count differs "
            f"({_table_separators(translated_text)} vs {_table_separators(source_text)})"
        )

    version = VERSION_RE.search(source_text)
    if version and version.group(1) not in translated_text:
        errors.append(f"version {version.group(1)} missing")

    residue = ''.join(sorted(set(CHINESE_RE.findall(_visible_text(translated_text)))))
    if residue:
        errors.append(f"Chinese characters remain outside code: {residue}")

    return errors


def validate_translated_texts(source_text, outputs):
    errors = []
    for lang in LANGUAGES:
        text = outputs.get(lang)
        if not text:
            errors.append(f"{lang}: missing output")
            continue
        for error in validate_pair(source_text, text):
            errors.append(f"{lang}: {error}")
    return errors


def language_dir(output_dir, lang):
    normalized = os.path.normpath(output_dir)
    if os.path.basename(normalized) == "languages":
        return os.path.join(normalized, lang)
    return os.path.join(output_dir, "languages", lang)


def validate_outputs(source_path, output_dir):
    try:
        source_text = _read(source_path)
    except OSError as e:
        return [f"cannot read source {source_path}: {e}"]

    source_name = os.path.basename(source_path)
    outputs = {}
    errors = []
    for lang in LANGUAGES:
        path = os.path.join(language_dir(output_dir, lang), source_name)
        if not os.path.isfile(path):
            errors.append(f"{lang}: missing {path}")
            continue
        try:
            text = _read(path)
        except OSError as e:
            errors.append(f"{lang}: cannot read {path}: {e}")
            continue
        if not text.strip():
            errors.append(f"{lang}: empty {path}")
            continue
        outputs[lang] = text

    if errors:
        return errors
    return validate_translated_texts(source_text, outputs)
