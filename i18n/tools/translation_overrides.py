"""Load human-reviewed overrides.

Files are optional and live under i18n/overrides/<kind>/<lang>.json:

    {
      "source sentence": "reviewed translation"
    }

An override is applied before the cache and before any provider. It is never
rewritten by the workflow, so it survives source edits. When the source
sentence changes, the key no longer matches and the entry stays in the file
for a human to update.
"""

import json
import os

from translation_backend import TranslationError

OVERRIDE_DIR = os.path.join('i18n', 'overrides')


def load(kind, lang):
    path = os.path.join(OVERRIDE_DIR, kind, f'{lang}.json')
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise TranslationError(f"cannot load override {path}: {e}")
    if not isinstance(data, dict):
        raise TranslationError(f"override {path} must be a JSON object")
    for source, target in data.items():
        if not isinstance(source, str) or not isinstance(target, str) or not target.strip():
            raise TranslationError(f"override {path} has an invalid entry: {source!r}")
    return data
