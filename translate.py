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
    ensure_source_terms,
    extract_source_terms,
    missing_source_terms,
    protect_terms,
    restore_placeholders,
    restore_source_terms,
)

DetectorFactory.seed = 0

def extract_english_segments(text):
    return extract_source_terms(text)

def protect_source_terms(text):
    return protect_terms(text)

def restore_protected_terms(translated, source):
    return ensure_source_terms(translated, source)

def restore_english_segments(translated, source):
    return restore_source_terms(translated, source)

def load_translation_cache(cache_file):
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            translations = json.load(f)
        for key in translations:
            translations[key] = clean_translation(restore_protected_terms(translations[key], key))
        return translations
    return {}

def save_translation_cache(cache_file, translations):
    for key in translations:
        translations[key] = clean_translation(restore_protected_terms(translations[key], key))
    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump(translations, f, ensure_ascii=False, indent=2)

def get_version(version_file):
    if os.path.exists(version_file):
        with open(version_file, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return None

def update_version(version_file):
    timestamp = str(int(time.time()))
    with open(version_file, 'w', encoding='utf-8') as f:
        f.write(timestamp)
    return timestamp

def contains_chinese(text):
    return any('\u4e00' <= char <= '\u9fff' for char in text)

def translate_text_qwen_mt(text, target_lang):
    api_key = os.getenv("AI_API_KEY")
    if not api_key:
        raise ValueError("AI_API_KEY environment variable is not set.")
    client = OpenAI(
        api_key=api_key,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    protected_text, protected_terms = protect_source_terms(text)
    messages = [
        {'role': 'user', 'content': protected_text}
    ]
    translation_options = {
        "source_lang": "zh",
        "target_lang": target_lang
    }
    try:
        completion = client.chat.completions.create(
            model="qwen-mt-plus",
            messages=messages,
            extra_body={
                "translation_options": translation_options
            }
        )
        translated_text = completion.choices[0].message.content
        translated_text = restore_placeholders(translated_text, protected_terms)
        return restore_protected_terms(translated_text, text)
    except Exception as e:
        print(f"Qwen-MT-Plus translation failed: {e}")
        return ""

def translate_text_google(text, target_lang):
    try:
        protected_text, protected_terms = protect_source_terms(text)
        translator = GoogleTranslator(source='zh-CN', target=target_lang)
        translated_text = translator.translate(protected_text)
        if translated_text is None:
            return ""
        translated_text = restore_placeholders(translated_text, protected_terms)
        return restore_protected_terms(translated_text, text)
    except Exception as e:
        print(f"Google Translate failed: {e}")
        return ""

def needs_fallback_translation(translated_text):
    return '\n' in translated_text or '"' in translated_text or PLACEHOLDER_RE.search(translated_text)

def clean_translation(text):
    return re.sub(r'\s+', ' ', text.replace('\n', '').replace('"', '')).strip()

def translate_po_file(input_file, output_file, target_lang_code, target_lang_name):
    lang_dir = os.path.dirname(output_file)
    lc_messages_dir = os.path.join('languages', target_lang_code, 'LC_MESSAGES')

    if not os.path.exists(lc_messages_dir):
        os.makedirs(lc_messages_dir)

    cache_file = os.path.join(lang_dir, f'cache_{target_lang_name}.json')
    version_file = os.path.join(lc_messages_dir, 'version')

    translations = load_translation_cache(cache_file)
    current_version = get_version(version_file)

    po = polib.pofile(input_file)

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
            translated_text = clean_translation(restore_source_terms(translations[msgid_text], msgid_text))
            if translated_text == "":
                print(f"Cached translation is empty for: {msgid_text}. Re-translating...")
            elif missing_source_terms(translated_text, msgid_text):
                print(f"Cached translation is missing protected terms for: {msgid_text}. Re-translating...")
            else:
                print(f"Using cached translation: {msgid_text} -> {translated_text}")
                entry.msgstr = translated_text
                if entry.fuzzy:
                    entry.fuzzy = False
                continue

        try:
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    time.sleep(0.5)
                    translated_text = translate_text_qwen_mt(msgid_text, target_lang_code)

                    if (not translated_text or
                        contains_chinese(translated_text) or
                        needs_fallback_translation(translated_text)):
                        print(f"Translation does not meet criteria using Qwen-MT-Plus. Using Google Translate...")
                        translated_text = translate_text_google(msgid_text, target_lang_code)

                    translated_text = clean_translation(ensure_source_terms(translated_text, msgid_text))

                    translations[msgid_text] = translated_text
                    print(f"New translation [{target_lang_code}]: {msgid_text} -> {translated_text}")
                    entry.msgstr = translated_text
                    if entry.fuzzy:
                        entry.fuzzy = False
                    break
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise e
                    print(f"Retry {attempt + 1}/{max_retries} for: {msgid_text}")
                    time.sleep(0.5)
        except Exception as e:
            print(f"Translation failed for: {msgid_text}")
            print(f"Error: {e}")
            if msgid_text in translations:
                del translations[msgid_text]
            continue

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

    if updated:
        po.save(output_file)
        save_translation_cache(cache_file, translations)
        new_version = update_version(version_file)
        print(f"Updated version from {current_version} to {new_version}")
    else:
        print("No translation updates.")
        no_update_file = os.path.join(os.path.dirname(output_file), f'{os.path.basename(output_file)}.no-update')
        with open(no_update_file, 'w', encoding='utf-8') as f:
            f.write("# No updates.\n")

if __name__ == '__main__':
    for lang_code, lang_name in [('en', 'English'), ('fa', 'Persian'), ('ru', 'Russian'), ('ko', 'Korean'), ('fr', 'French')]:
        print(f"\nTranslating to {lang_name} ({lang_code})...")
        input_file = f'po/{lang_code}.po'
        output_file = f'po/{lang_code}.po'
        translate_po_file(input_file, output_file, lang_code, lang_name)
