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
from translation_glossary import check as glossary_check, provider_terms
from translation_overrides import load as load_overrides
from text_quality import CJK_PUNCT_RE, chinese_punctuation, normalize_punctuation
from readme_validation import (
    evaluate_outputs,
    evaluate_translated_texts,
    semantic_check_and_repair,
)

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

SOURCE_HASH_FILE = os.path.join('i18n', 'languages', '.readme-source.sha256')
REPORT_FILE = 'readme-quality-report.json'

CHECKPOINT_EVERY = 50
_CACHE_FILE = None
_OVERRIDES = {}
_FORCE_RETRANSLATE = False


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


def _validate_override(override, source_text, target_lang):
    if contains_chinese(override) or chinese_punctuation(override) or '\n' in override:
        raise TranslationError(f"override violates quality rules for {source_text!r}")
    glossary = glossary_check(target_lang, source_text, override)
    if glossary['errors']:
        raise TranslationError(
            f"override glossary mismatch for {source_text!r}: {'; '.join(glossary['errors'])}"
        )


def translate_text(text, target_lang, translations):
    override = _OVERRIDES.get(target_lang, {}).get(text)
    if override:
        _validate_override(override, text, target_lang)
        logging.info(f"使用人工 override: '{text}' -> '{override}'")
        return override

    cache_key = get_cache_key(text, target_lang)
    if not _FORCE_RETRANSLATE and cache_key in translations:
        cached = normalize_punctuation(translations[cache_key])
        if cached and not contains_chinese(cached) and not chinese_punctuation(cached):
            glossary = glossary_check(target_lang, text, cached)
            if not glossary['errors']:
                if cached != translations[cache_key]:
                    translations[cache_key] = cached
                logging.info(f"从缓存中获取翻译: '{text}' -> '{cached}'")
                return cached
        logging.info(f"缓存译文未通过质检，重新翻译: '{text}'")

    terms = provider_terms(target_lang, text)
    glossary_errors = None
    for attempt in range(2):
        translated = translate_with_backend(
            text,
            target_lang,
            terms=terms,
            postprocess=lambda value: normalize_punctuation(value.strip()),
            accept=lambda value: (
                bool(value)
                and not contains_chinese(value)
                and not chinese_punctuation(value)
                and '\n' not in value
            ),
        )
        glossary = glossary_check(target_lang, text, translated)
        if not glossary['errors']:
            break
        glossary_errors = glossary['errors']
        logging.warning(
            "术语校验未通过 (attempt %d/2): %r -> %r; %s",
            attempt + 1, text, translated, "; ".join(glossary_errors),
        )
    else:
        raise TranslationError(
            f"glossary validation failed for {text!r}: {'; '.join(glossary_errors or [])}; "
            f"last={translated!r}"
        )

    translations[cache_key] = translated
    if _CACHE_FILE and len(translations) % CHECKPOINT_EVERY == 0:
        save_translation_cache(_CACHE_FILE, translations)
        logging.info(f"已写入缓存检查点: {len(translations)} 条")
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
    if not text:
        return text
    if not CHINESE_RE.search(text):
        return normalize_punctuation(text)
    return translate_text(text, target_lang, translations)


def translate_segment(segment, target_lang, translations):
    if not segment.strip() or not should_translate(segment):
        return segment
    if not CHINESE_RE.search(segment) and not CJK_PUNCT_RE.search(segment):
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
    if not should_translate(line):
        return line
    if not CHINESE_RE.search(line) and not CJK_PUNCT_RE.search(line):
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


def retranslate_line(source_line, target_lang, translations):
    global _FORCE_RETRANSLATE
    _FORCE_RETRANSLATE = True
    try:
        return translate_markdown_line(source_line, target_lang, translations)
    finally:
        _FORCE_RETRANSLATE = False


def translate_readme(input_file, output_dir):
    global _CACHE_FILE, _OVERRIDES
    cache_file = 'translation_cache_readme.json'
    _CACHE_FILE = cache_file
    _OVERRIDES = {lang: load_overrides('readme', lang) for lang in LANGUAGES}

    with open(input_file, 'rb') as f:
        source_digest = hashlib.sha256(f.read()).hexdigest()
    source_filename = os.path.basename(input_file)

    existing_errors, _ = evaluate_outputs(input_file, output_dir)
    if read_source_hash(SOURCE_HASH_FILE) == source_digest and not existing_errors:
        logging.info("README 源文件未变化，现有翻译通过质检，跳过翻译。")
        return
    if existing_errors:
        logging.info(
            "现有 README 翻译未通过质检，将重新生成: %s",
            "; ".join(existing_errors[:5]),
        )

    translations = load_translation_cache(cache_file)
    logging.info(f"缓存文件 '{cache_file}' 加载完成，共有 {len(translations)} 条缓存记录。")

    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    logging.info(f"读取 '{input_file}' 完成，共 {len(content)} 个字符。")

    outputs = {}
    for lang_code, lang_name in LANGUAGES.items():
        logging.info(f"开始翻译到 {lang_name} ({lang_code})")
        outputs[lang_code] = translate_markdown_content(content, lang_code, translations)
        logging.info(f"{lang_name} 翻译内容重新组合完成。")

    semantic_reports = {}
    for lang_code in list(outputs):
        logging.info(f"开始语义抽检 ({lang_code})")
        outputs[lang_code], semantic_reports[lang_code] = semantic_check_and_repair(
            content,
            outputs[lang_code],
            lang_code,
            lambda source_line, lang=lang_code: retranslate_line(source_line, lang, translations),
        )

    errors, metrics = evaluate_translated_texts(content, outputs, semantic_reports)
    if errors:
        raise TranslationError(
            "translated README failed quality gates: " + "; ".join(errors[:10])
        )

    report_tmp = REPORT_FILE + '.tmp'
    with open(report_tmp, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)
    os.replace(report_tmp, REPORT_FILE)

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
    logging.info("所有翻译完成，质检报告与源文件校验值已保存。")


if __name__ == "__main__":
    input_readme = sys.argv[1] if len(sys.argv) > 1 else 'README.md'
    output_directory = sys.argv[2] if len(sys.argv) > 2 else '.'
    try:
        translate_readme(input_readme, output_directory)
    except TranslationError as e:
        logging.error(f"翻译中止，未写入任何 README: {e}")
        raise SystemExit(1)
