import time
import json
import os
import re
import polib
from translation_terms import PLACEHOLDER_RE
from translation_backend import (
    TranslationError,
    contains_chinese,
    translate as translate_with_backend,
)
from translation_glossary import check as glossary_check, provider_terms
from translation_overrides import load as load_overrides
from text_quality import chinese_chars, chinese_punctuation, normalize_punctuation


def load_translation_cache(cache_file):
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            translations = json.load(f)
        for key in translations:
            translations[key] = clean_translation(normalize_punctuation(translations[key]))
        return translations
    return {}


def save_translation_cache(cache_file, translations):
    for key in translations:
        translations[key] = clean_translation(normalize_punctuation(translations[key]))
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


def needs_fallback_translation(translated_text):
    return '\n' in translated_text or '"' in translated_text or PLACEHOLDER_RE.search(translated_text)


def clean_translation(text):
    return re.sub(r'\s+', ' ', text.replace('\n', '').replace('"', '')).strip()


def _validate_po_override(override, msgid_text, target_lang_code):
    text = override.strip()
    if not text or '\n' in text or chinese_chars(text) or chinese_punctuation(text):
        raise TranslationError(f"override violates quality rules for {msgid_text!r}")
    glossary = glossary_check(target_lang_code, msgid_text, text)
    if glossary['errors']:
        raise TranslationError(
            f"override glossary mismatch for {msgid_text!r}: {'; '.join(glossary['errors'])}"
        )
    return text


def translate_po_file(input_file, output_file, target_lang_code, target_lang_name):
    lang_dir = os.path.dirname(output_file)
    lc_messages_dir = os.path.join('i18n/languages', target_lang_code, 'LC_MESSAGES')

    if not os.path.exists(lc_messages_dir):
        os.makedirs(lc_messages_dir)

    cache_file = os.path.join(lang_dir, f'cache_{target_lang_name}.json')
    version_file = os.path.join(lc_messages_dir, 'version')

    translations = load_translation_cache(cache_file)
    overrides = load_overrides('po', target_lang_code)
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

        if msgid_text in overrides:
            translated_text = _validate_po_override(overrides[msgid_text], msgid_text, target_lang_code)
            print(f"Using override: {msgid_text} -> {translated_text}")
            entry.msgstr = translated_text
            if 'fuzzy' in entry.flags:
                entry.flags.remove('fuzzy')
            continue

        if msgid_text in translations:
            translated_text = clean_translation(normalize_punctuation(translations[msgid_text]))
            valid = (
                bool(translated_text)
                and not contains_chinese(translated_text)
                and not chinese_punctuation(translated_text)
            )
            if valid:
                glossary = glossary_check(target_lang_code, msgid_text, translated_text)
                valid = not glossary['errors']
            if valid:
                print(f"Using cached translation: {msgid_text} -> {translated_text}")
                entry.msgstr = translated_text
                if 'fuzzy' in entry.flags:
                    entry.flags.remove('fuzzy')
                continue
            print(f"Cached translation failed quality checks; re-translating: {msgid_text}")

        terms = provider_terms(target_lang_code, msgid_text)
        glossary_errors = None
        for attempt in range(2):
            translated_text = translate_with_backend(
                msgid_text,
                target_lang_code,
                terms=terms,
                postprocess=lambda value: clean_translation(normalize_punctuation(value)),
                accept=lambda value: (
                    bool(value)
                    and not contains_chinese(value)
                    and not chinese_punctuation(value)
                    and not needs_fallback_translation(value)
                ),
            )
            glossary = glossary_check(target_lang_code, msgid_text, translated_text)
            if not glossary['errors']:
                break
            glossary_errors = glossary['errors']
            print(
                f"Glossary mismatch (attempt {attempt + 1}/2) [{target_lang_code}]: "
                f"{msgid_text} -> {translated_text}; {'; '.join(glossary_errors)}"
            )
        else:
            raise TranslationError(
                f"glossary validation failed for {msgid_text!r}: {'; '.join(glossary_errors or [])}"
            )

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

    quality = {"entries": 0, "glossary_terms": 0, "glossary_hits": 0}
    for entry in po:
        if not entry.msgid or entry.obsolete:
            continue
        quality["entries"] += 1
        if chinese_chars(entry.msgstr) or chinese_punctuation(entry.msgstr):
            raise TranslationError(
                f"{target_lang_code}: Chinese residue in entry {entry.msgid!r}: {entry.msgstr!r}"
            )
        glossary = glossary_check(target_lang_code, entry.msgid, entry.msgstr)
        if glossary['errors']:
            raise TranslationError(
                f"{target_lang_code}: entry {entry.msgid!r}: {'; '.join(glossary['errors'])}"
            )
        quality["glossary_terms"] += glossary['terms']
        quality["glossary_hits"] += glossary['hits']
    hit_rate = (quality["glossary_hits"] / quality["glossary_terms"]) if quality["glossary_terms"] else 1.0
    print(
        f"[{target_lang_code}] PO quality: entries={quality['entries']} "
        f"glossary_hits={quality['glossary_hits']}/{quality['glossary_terms']} "
        f"hit_rate={hit_rate:.3f} chinese=0"
    )

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
