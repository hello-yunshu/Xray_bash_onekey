import os
import json
import re
import sys
import hashlib
import logging

from translation_backend import (
    TranslationError,
    contains_chinese,
    translate as translate_with_backend,
)
from readme_validation import validate_outputs, validate_translated_texts

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CHINESE_RE = re.compile(r'[\u4e00-\u9fff]')
PROTECTED_INLINE_RE = re.compile(
    r'(`[^`]*`|!\[[^\]]*\]\([^)]+\)|\[[^\]]*\]\([^)]+\)|<[^>]+>|https?://\S+)'
)
LINK_RE = re.compile(r'\[([^\]]*)\]\(([^)]+)\)')
MARKDOWN_PREFIX_PATTERNS = [
    re.compile(r'^(\s{0,3}#{1,6}\s+)(.*)$'),
    re.compile(r'^(\s*(?:[-*+]|\d+\.)\s+(?:\[[ xX]\]\s+)?)(.*)$'),
    re.compile(r'^(\s*>\s?)(.*)$'),
]

LANGUAGES = {
    'en': 'english',
    'ru': 'russian',
    'fa': 'persian',
    'fr': 'french',
    'ko': 'korean'
}

# Records the SHA-256 of the README.md that produced the committed
# translations. When the source and the validated outputs are unchanged there
# is nothing to translate.
SOURCE_HASH_FILE = os.path.join('i18n', 'languages', '.readme-source.sha256')


def read_source_hash(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return None


def write_source_hash(path, digest):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(digest + '\n')
    os.replace(tmp, path)


def load_translation_cache(cache_file):
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def save_translation_cache(cache_file, translations):
    tmp = cache_file + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(translations, f, ensure_ascii=False, indent=4)
    os.replace(tmp, cache_file)


def get_cache_key(text, target_lang):
    return f"{target_lang}::{text}"


def translate_text(text, target_lang, translations):
    cache_key = get_cache_key(text, target_lang)
    if cache_key in translations:
        logging.info(f"从缓存中获取翻译: '{text}' -> '{translations[cache_key]}'")
        return translations[cache_key]

    translated = translate_with_backend(
        text,
        target_lang,
        postprocess=lambda value: value.strip(),
        accept=lambda value: (
            bool(value)
            and not contains_chinese(value)
            and '\n' not in value
        ),
    )
    translations[cache_key] = translated
    logging.info(f"翻译成功: '{text}' -> '{translated}'")
    return translated


def should_translate(segment):
    skip_patterns = [
        r'\[简体中文\]\(README\.md\)'
    ]
    for pattern in skip_patterns:
        if re.search(pattern, segment):
            logging.info(f"跳过翻译的段落: {segment}")
            return False
    return True


def translate_plain_text(text, target_lang, translations):
    if not text or not CHINESE_RE.search(text):
        return text
    return translate_text(text, target_lang, translations)


def translate_segment(segment, target_lang, translations):
    if not segment.strip() or not CHINESE_RE.search(segment) or not should_translate(segment):
        return segment

    translated_parts = []
    last_index = 0
    for match in PROTECTED_INLINE_RE.finditer(segment):
        translated_parts.append(
            translate_plain_text(segment[last_index:match.start()], target_lang, translations)
        )
        token = match.group(0)
        link = LINK_RE.fullmatch(token)
        if link and not link.group(1).startswith('!['):
            # Translate the visible label but keep the destination byte-for-byte.
            label = translate_plain_text(link.group(1), target_lang, translations)
            translated_parts.append(f"[{label}]({link.group(2)})")
        else:
            translated_parts.append(token)
        last_index = match.end()
    translated_parts.append(translate_plain_text(segment[last_index:], target_lang, translations))
    return ''.join(translated_parts)


def is_table_separator(line):
    return bool(re.match(r'^\s*\|?[\s:.-]+\|[\s|:.-]*$', line))


def translate_table_row(line, target_lang, translations):
    if is_table_separator(line):
        return line

    cells = line.split('|')
    translated_cells = []
    for cell in cells:
        match = re.match(r'^(\s*)(.*?)(\s*)$', cell)
        leading, content, trailing = match.groups()
        translated_cells.append(
            f"{leading}{translate_segment(content, target_lang, translations)}{trailing}"
        )
    return '|'.join(translated_cells)


def translate_markdown_line(line, target_lang, translations):
    if not CHINESE_RE.search(line) or not should_translate(line):
        return line
    if re.match(r'^\s{0,3}([-*_]\s*){3,}$', line):
        return line
    if line.strip().startswith('|') and '|' in line:
        return translate_table_row(line, target_lang, translations)

    for pattern in MARKDOWN_PREFIX_PATTERNS:
        match = pattern.match(line)
        if match:
            return match.group(1) + translate_segment(match.group(2), target_lang, translations)

    return translate_segment(line, target_lang, translations)


def translate_markdown_content(content, target_lang, translations):
    translated_lines = []
    in_code_block = False

    for raw_line in content.splitlines(keepends=True):
        line = raw_line.rstrip('\r\n')
        newline = raw_line[len(line):]
        stripped = line.lstrip()

        if stripped.startswith('```') or stripped.startswith('~~~'):
            in_code_block = not in_code_block
            translated_lines.append(raw_line)
            continue

        if in_code_block:
            translated_lines.append(raw_line)
            continue

        translated_lines.append(
            translate_markdown_line(line, target_lang, translations) + newline
        )

    return ''.join(translated_lines)


def language_output_dir(output_dir, lang_code):
    normalized = os.path.normpath(output_dir)
    if os.path.basename(normalized) == 'languages':
        return os.path.join(normalized, lang_code)
    return os.path.join(output_dir, 'languages', lang_code)


def translate_readme(input_file, output_dir):
    cache_file = 'translation_cache_readme.json'

    with open(input_file, 'rb') as f:
        source_digest = hashlib.sha256(f.read()).hexdigest()
    source_filename = os.path.basename(input_file)

    # A tool/workflow-only change must not re-translate an unchanged README.
    # The committed outputs still have to pass the structural validation: a
    # stale partial translation must trigger regeneration, not a silent skip.
    existing_errors = validate_outputs(input_file, output_dir)
    if read_source_hash(SOURCE_HASH_FILE) == source_digest and not existing_errors:
        logging.info("README 源文件未变化，现有翻译通过校验，跳过翻译。")
        return
    if existing_errors:
        logging.info(
            "现有 README 翻译未通过校验，将重新生成: %s",
            "; ".join(existing_errors[:5]),
        )

    translations = load_translation_cache(cache_file)
    logging.info(f"缓存文件 '{cache_file}' 加载完成，共有 {len(translations)} 条缓存记录。")

    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    logging.info(f"读取 '{input_file}' 完成，共 {len(content)} 个字符。")

    # Build every language in memory first. A 429/failure in any language
    # aborts the run before a partial README is written or staged.
    outputs = {}
    for lang_code, lang_name in LANGUAGES.items():
        logging.info(f"开始翻译到 {lang_name} ({lang_code})")
        outputs[lang_code] = translate_markdown_content(content, lang_code, translations)
        logging.info(f"{lang_name} 翻译内容重新组合完成。")

    errors = validate_translated_texts(content, outputs)
    if errors:
        raise TranslationError(
            "translated README failed validation: " + "; ".join(errors[:10])
        )

    tmp_files = []
    try:
        for lang_code, translated_content in outputs.items():
            lang_dir = language_output_dir(output_dir, lang_code)
            os.makedirs(lang_dir, exist_ok=True)
            output_file = os.path.join(lang_dir, source_filename)
            tmp_file = output_file + ".tmp"
            with open(tmp_file, 'w', encoding='utf-8') as f:
                f.write(translated_content)
            tmp_files.append((tmp_file, output_file))
    except Exception:
        for tmp_file, _ in tmp_files:
            try:
                os.unlink(tmp_file)
            except OSError:
                pass
        raise

    for tmp_file, output_file in tmp_files:
        os.replace(tmp_file, output_file)
        logging.info(f"翻译完成，文件保存至: {output_file}")

    save_translation_cache(cache_file, translations)
    write_source_hash(SOURCE_HASH_FILE, source_digest)
    logging.info("所有翻译完成，并已保存缓存与源文件校验值。")


if __name__ == "__main__":
    input_readme = sys.argv[1] if len(sys.argv) > 1 else 'README.md'
    output_directory = sys.argv[2] if len(sys.argv) > 2 else '.'
    try:
        translate_readme(input_readme, output_directory)
    except TranslationError as e:
        logging.error(f"翻译中止，未写入任何 README: {e}")
        raise SystemExit(1)
