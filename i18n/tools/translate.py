import time
import json
import os
import re
import polib
from openai import OpenAI
from deep_translator import GoogleTranslator
from langdetect import detect, DetectorFactory
from translation_terms import (
    PLACEHOLDER_RE,
    protect_terms,
    restore_placeholders,
)

DetectorFactory.seed = 0

SHORT_STRING_THRESHOLD = 15
TRANSLATION_MAX_ATTEMPTS = 5
TRANSLATION_REQUEST_INTERVAL = 1.0
_LAST_REQUEST_AT = 0.0


class TranslationError(Exception):
    pass


def _rate_limit():
    """Keep all machine-translation requests serial and below Google's 5/s."""
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
            translations = json.load(f)
        for key in translations:
            translations[key] = clean_translation(translations[key])
        return translations
    return {}


def save_translation_cache(cache_file, translations):
    for key in translations:
        translations[key] = clean_translation(translations[key])
    tmp = cache_file + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(translations, f, ensure_ascii=False, indent=2)
    os.replace(tmp, cache_file)


def get_version(version_file):
    if os.path.exists(version_file):
        with open(version_file, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return None


def update_version(version_file):
    timestamp = str(int(time.time()))
    tmp = version_file + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(timestamp)
    os.replace(tmp, version_file)
    return timestamp


def contains_chinese(text):
    return any('\u4e00' <= char <= '\u9fff' for char in text)


def translate_text_qwen_mt(text, target_lang):
    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        raise TranslationError("AI_API_KEY environment variable is not set.")
    client = OpenAI(
        api_key=api_key,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    protected_text, protected_terms = protect_terms(text)
    messages = [
        {'role': 'user', 'content': protected_text}
    ]
    translation_options = {
        "source_lang": "zh",
        "target_lang": target_lang
    }
    last_error = None
    for attempt in range(TRANSLATION_MAX_ATTEMPTS):
        _rate_limit()
        try:
            completion = client.chat.completions.create(
                model="qwen-mt-plus",
                messages=messages,
                extra_body={
                    "translation_options": translation_options
                }
            )
            translated_text = completion.choices[0].message.content
            translated_text = clean_translation(translated_text)
            if len(text) < SHORT_STRING_THRESHOLD:
                translated_text = translated_text.lower()
            translated_text = restore_placeholders(translated_text, protected_terms)
            return translated_text
        except Exception as e:
            last_error = e
            print(f"Qwen-MT-Plus translation failed (attempt {attempt + 1}/{TRANSLATION_MAX_ATTEMPTS}): {e}")
            if attempt < TRANSLATION_MAX_ATTEMPTS - 1:
                _retry_sleep(attempt)
    raise TranslationError(f"Qwen-MT-Plus failed after retries: {last_error}")


def translate_text_google(text, target_lang):
    last_error = None
    for attempt in range(TRANSLATION_MAX_ATTEMPTS):
        _rate_limit()
        try:
            protected_text, protected_terms = protect_terms(text)
            translator = GoogleTranslator(source='zh-CN', target=target_lang)
            translated_text = translator.translate(protected_text)
            if translated_text is None:
                raise TranslationError("Google Translate returned None")
            translated_text = clean_translation(translated_text)
            if len(text) < SHORT_STRING_THRESHOLD:
                translated_text = translated_text.lower()
            translated_text = restore_placeholders(translated_text, protected_terms)
            return translated_text
        except Exception as e:
            last_error = e
            print(f"Google Translate failed (attempt {attempt + 1}/{TRANSLATION_MAX_ATTEMPTS}): {e}")
            if attempt < TRANSLATION_MAX_ATTEMPTS - 1:
                _retry_sleep(attempt)
    raise TranslationError(f"Google Translate failed after retries: {last_error}")


def needs_fallback_translation(translated_text):
    return '\n' in translated_text or '"' in translated_text or PLACEHOLDER_RE.search(translated_text)


def clean_translation(text):
    return re.sub(r'\s+', ' ', text.replace('\n', '').replace('"', '')).strip()


def translate_po_file(input_file, output_file, target_lang_code, target_lang_name):
    lang_dir = os.path.dirname(output_file)
    lc_messages_dir = os.path.join('i18n/languages', target_lang_code, 'LC_MESSAGES')

    if not os.path.exists(lc_messages_dir):
        os.makedirs(lc_messages_dir)

    cache_file = os.path.join(lang_dir, f'cache_{target_lang_name}.json')
    version_file = os.path.join(lc_messages_dir, 'version')

    translations = load_translation_cache(cache_file)
    current_version = get_version(version_file)

    po = polib.pofile(input_file)

    po_fallback_count = 0
    for entry in po:
        if entry.msgid and entry.msgid not in translations and entry.msgstr and not entry.fuzzy:
            translations[entry.msgid] = entry.msgstr
            po_fallback_count += 1
    if po_fallback_count > 0:
        print(f"Loaded {po_fallback_count} translations from .po file as cache fallback")

    original_msgstrs = {}
    original_fuzzy = {}
    for entry in po:
        if entry.msgid:
            original_msgstrs[entry.msgid] = entry.msgstr
            original_fuzzy[entry.msgid] = entry.fuzzy

    for entry in po:
        if not entry.msgid:
            continue

        msgid_text = entry.msgid

        if msgid_text in translations:
            translated_text = clean_translation(translations[msgid_text])
            if translated_text == "":
                print(f"Cached translation is empty for: {msgid_text}. Re-translating...")
            else:
                print(f"Using cached translation: {msgid_text} -> {translated_text}")
                entry.msgstr = translated_text
                if 'fuzzy' in entry.flags:
                    entry.flags.remove('fuzzy')
                continue

        translated_text = ""
        try:
            translated_text = translate_text_qwen_mt(msgid_text, target_lang_code)
            if (not translated_text or
                contains_chinese(translated_text) or
                needs_fallback_translation(translated_text)):
                print("Qwen-MT-Plus output does not meet criteria. Using Google Translate...")
                translated_text = translate_text_google(msgid_text, target_lang_code)
        except TranslationError as e:
            print(f"Qwen-MT-Plus unavailable ({e}); falling back to Google Translate")
            translated_text = translate_text_google(msgid_text, target_lang_code)

        translated_text = clean_translation(translated_text)
        if (not translated_text or
            contains_chinese(translated_text) or
            needs_fallback_translation(translated_text)):
            raise TranslationError(f"no valid translation for: {msgid_text}")

        translations[msgid_text] = translated_text
        print(f"New translation [{target_lang_code}]: {msgid_text} -> {translated_text}")
        entry.msgstr = translated_text
        if 'fuzzy' in entry.flags:
            entry.flags.remove('fuzzy')

    updated = False
    for entry in po:
        if entry.msgid:
            if entry.msgid not in original_msgstrs:
                if entry.msgstr:
                    updated = True
                    break
            elif entry.msgstr != original_msgstrs[entry.msgid]:
                updated = True
                break
            elif entry.fuzzy != original_fuzzy.get(entry.msgid, False):
                updated = True
                break

    if po.obsolete_entries():
        for entry in po.obsolete_entries():
            if entry.msgid in translations:
                del translations[entry.msgid]
                print(f"Removed obsolete translation: {entry.msgid}")
        for entry in list(po.obsolete_entries()):
            po.remove(entry)
        updated = True

    missing = [
        entry.msgid for entry in po
        if entry.msgid and not entry.obsolete
        and (not entry.msgstr.strip() or entry.fuzzy)
    ]
    if missing:
        raise TranslationError(
            f"{target_lang_code}: {len(missing)} untranslated/fuzzy entries remain; "
            f"first={missing[0]!r}"
        )

    # Do not write anything until the whole language is complete. The caller
    # commits only after every language returns a validated result.
    return {
        'lang_code': target_lang_code,
        'po': po,
        'translations': translations,
        'updated': updated,
        'output_file': output_file,
        'cache_file': cache_file,
        'version_file': version_file,
        'current_version': current_version,
    }


def write_translation_result(result):
    if not result['updated']:
        print(f"No translation updates for {result['lang_code']}.")
        no_update_file = f"{result['output_file']}.no-update"
        with open(no_update_file, 'w', encoding='utf-8') as f:
            f.write("# No updates.\n")
        return
    output_file = result['output_file']
    tmp_output = output_file + ".tmp"
    result['po'].save(tmp_output)
    save_translation_cache(result['cache_file'], result['translations'])
    os.replace(tmp_output, output_file)
    new_version = update_version(result['version_file'])
    print(f"Updated {result['lang_code']} version from {result['current_version']} to {new_version}")

if __name__ == '__main__':
    results = []
    try:
        for lang_code, lang_name in [('en', 'English'), ('fa', 'Persian'), ('ru', 'Russian'), ('ko', 'Korean'), ('fr', 'French')]:
            print(f"\nTranslating to {lang_name} ({lang_code})...")
            input_file = f'i18n/po/{lang_code}.po'
            output_file = f'i18n/po/{lang_code}.po'
            results.append(translate_po_file(input_file, output_file, lang_code, lang_name))
    except TranslationError as e:
        print(f"Translation aborted; no files were written: {e}", flush=True)
        raise SystemExit(1)

    # All languages validated in memory. Only now write PO/cache/version files.
    for result in results:
        write_translation_result(result)
