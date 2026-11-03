"""Load and enforce the repository glossary.

Adding a term only requires editing i18n/glossary/<lang>.json.
"""

import json
import os

from text_quality import contains_term, visible_text
from translation_backend import TranslationError

GLOSSARY_DIR = os.path.join('i18n', 'glossary')
_CACHE = {}


class GlossaryError(TranslationError):
    pass


def load(lang):
    if lang in _CACHE:
        return _CACHE[lang]
    path = os.path.join(GLOSSARY_DIR, f'{lang}.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise GlossaryError(f"cannot load glossary {path}: {e}")
    terms = data.get('terms')
    if not isinstance(terms, list) or not terms:
        raise GlossaryError(f"glossary {path} must contain a non-empty terms list")
    for term in terms:
        source = term.get('source')
        targets = term.get('target')
        if not source or not isinstance(targets, list) or not targets:
            raise GlossaryError(f"glossary {path} has an invalid term: {term!r}")
    _CACHE[lang] = data
    return data


def provider_terms(lang, source_text):
    """Terminology hints for providers that accept a terms array."""
    visible = visible_text(source_text)
    active = []
    seen = set()
    for term in load(lang)['terms']:
        source = term['source']
        if source in seen:
            continue
        if contains_term(visible, source):
            active.append({"source": source, "target": term['target'][0]})
            seen.add(source)
    active.sort(key=lambda item: len(item['source']), reverse=True)
    return active


def check(lang, source_text, translated_text):
    data = load(lang)
    source_visible = visible_text(source_text)
    target_visible = visible_text(translated_text)
    total = 0
    hits = 0
    missing = []
    for term in data['terms']:
        source = term['source']
        if not contains_term(source_visible, source):
            continue
        total += 1
        if any(contains_term(target_visible, target, case_sensitive=False)
               for target in term['target']):
            hits += 1
        else:
            missing.append(source)
    forbidden = [
        item for item in data.get('forbidden', [])
        if contains_term(target_visible, item, case_sensitive=True)
    ]
    hit_rate = (hits / total) if total else 1.0
    errors = []
    if missing:
        errors.append(f"glossary terms missing: {', '.join(missing)}")
    if forbidden:
        errors.append(f"forbidden translations present: {', '.join(forbidden)}")
    return {
        "terms": total,
        "hits": hits,
        "hit_rate": hit_rate,
        "missing": missing,
        "forbidden": forbidden,
        "errors": errors,
    }
