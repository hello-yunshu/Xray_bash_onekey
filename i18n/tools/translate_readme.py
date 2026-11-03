import os
import json
import re
import sys
import time
from deep_translator import GoogleTranslator
import logging
from translation_terms import protect_terms, restore_placeholders

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CHINESE_RE = re.compile(r'[\u4e00-\u9fff]')
PROTECTED_INLINE_RE = re.compile(
    r'(`[^`]*`|!\[[^\]]*\]\([^)]+\)|\[[^\]]*\]\([^)]+\)|<[^>]+>|https?://\S+)'
)
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

TRANSLATION_MAX_ATTEMPTS = 5
TRANSLATION_REQUEST_INTERVAL = 1.0
_LAST_REQUEST_AT = 0.0


class TranslationError(Exception):
    pass


def _rate_limit():
    global _LAST_REQUEST_AT
    now = time.monotonic()
    wait = TRANSLATION_REQUEST_INTERVAL - (now - _LAST_REQUEST_AT)
    if wait > 0:
        time.sleep(wait)
    _LAST_REQUEST_AT = time.monotonic()


def _retry_sleep(attempt):
    time.sleep(min(30, TRANSLATION_REQUEST_INTERVAL * (2 ** attempt)))

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

def translate_text(text, target_lang, translator, translations):
    cache_key = get_cache_key(text, target_lang)
    if cache_key in translations:
        logging.info(f"从缓存中获取翻译: '{text}' -> '{translations[cache_key]}'")
        return translations[cache_key]

    last_error = None
    for attempt in range(TRANSLATION_MAX_ATTEMPTS):
        _rate_limit()
        try:
            protected_text, protected_terms = protect_terms(text)
            translated = translator.translate(protected_text)
            if translated is None:
                raise TranslationError("translator returned None")
            translated = restore_placeholders(translated, protected_terms)
            translations[cache_key] = translated
            logging.info(f"翻译成功: '{text}' -> '{translated}'")
            return translated
        except Exception as e:
            last_error = e
            logging.error(
                f"翻译失败 (attempt {attempt + 1}/{TRANSLATION_MAX_ATTEMPTS}): {text}\n错误: {e}"
            )
            if attempt < TRANSLATION_MAX_ATTEMPTS - 1:
                _retry_sleep(attempt)
    raise TranslationError(f"Google Translate failed for {text!r}: {last_error}")

def should_translate(segment):
    skip_patterns = [
        r'\[简体中文\]\(README\.md\)'
    ]
    for pattern in skip_patterns:
        if re.search(pattern, segment):
            logging.info(f"跳过翻译的段落: {segment}")
            return False
    return True

def translate_plain_text(text, target_lang, translator, translations):
    if not text or not CHINESE_RE.search(text):
        return text
    return translate_text(text, target_lang, translator, translations)

def translate_segment(segment, target_lang, translator, translations):
    if not segment.strip() or not CHINESE_RE.search(segment) or not should_translate(segment):
        return segment

    translated_parts = []
    last_index = 0
    for match in PROTECTED_INLINE_RE.finditer(segment):
        translated_parts.append(
            translate_plain_text(segment[last_index:match.start()], target_lang, translator, translations)
        )
        translated_parts.append(match.group(0))
        last_index = match.end()
    translated_parts.append(translate_plain_text(segment[last_index:], target_lang, translator, translations))
    return ''.join(translated_parts)

def is_table_separator(line):
    return bool(re.match(r'^\s*\|?[\s:.-]+\|[\s|:.-]*$', line))

def translate_table_row(line, target_lang, translator, translations):
    if is_table_separator(line):
        return line

    cells = line.split('|')
    translated_cells = []
    for cell in cells:
        match = re.match(r'^(\s*)(.*?)(\s*)$', cell)
        leading, content, trailing = match.groups()
        translated_cells.append(
            f"{leading}{translate_segment(content, target_lang, translator, translations)}{trailing}"
        )
    return '|'.join(translated_cells)

def translate_markdown_line(line, target_lang, translator, translations):
    if not CHINESE_RE.search(line) or not should_translate(line):
        return line
    if re.match(r'^\s{0,3}([-*_]\s*){3,}$', line):
        return line
    if line.strip().startswith('|') and '|' in line:
        return translate_table_row(line, target_lang, translator, translations)

    for pattern in MARKDOWN_PREFIX_PATTERNS:
        match = pattern.match(line)
        if match:
            return match.group(1) + translate_segment(match.group(2), target_lang, translator, translations)

    return translate_segment(line, target_lang, translator, translations)

def translate_markdown_content(content, target_lang, translator, translations):
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
            translate_markdown_line(line, target_lang, translator, translations) + newline
        )

    return ''.join(translated_lines)

def language_output_dir(output_dir, lang_code):
    normalized = os.path.normpath(output_dir)
    if os.path.basename(normalized) == 'languages':
        return os.path.join(normalized, lang_code)
    return os.path.join(output_dir, 'languages', lang_code)

def translate_readme(input_file, output_dir):
    cache_file = 'translation_cache_readme.json'
    translations = load_translation_cache(cache_file)
    logging.info(f"缓存文件 '{cache_file}' 加载完成，共有 {len(translations)} 条缓存记录。")

    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    logging.info(f"读取 '{input_file}' 完成，共 {len(content)} 个字符。")

    source_filename = os.path.basename(input_file)

    # Build every language in memory first. A 429/failure in any language
    # aborts the run before a partial README is written or staged.
    outputs = {}
    for lang_code, lang_name in LANGUAGES.items():
        logging.info(f"开始翻译到 {lang_name} ({lang_code})")
        try:
            translator = GoogleTranslator(source='zh-CN', target=lang_code)
        except Exception as e:
            raise TranslationError(f"初始化翻译器失败 ({lang_code}): {e}")

        translated_content = translate_markdown_content(content, lang_code, translator, translations)
        logging.info(f"{lang_name} 翻译内容重新组合完成。")
        outputs[lang_code] = translated_content

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
    logging.info("所有翻译完成，并已保存缓存。")

if __name__ == "__main__":
    input_readme = sys.argv[1] if len(sys.argv) > 1 else 'README.md'
    output_directory = sys.argv[2] if len(sys.argv) > 2 else '.'
    try:
        translate_readme(input_readme, output_directory)
    except TranslationError as e:
        logging.error(f"翻译中止，未写入任何 README: {e}")
        raise SystemExit(1)
