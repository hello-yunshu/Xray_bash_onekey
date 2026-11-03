"""Fail the translation workflow when a README output is incomplete."""

import json
import os
import sys

from readme_validation import evaluate_outputs


def _load_semantic_report():
    path = 'readme-quality-report.json'
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    result = {}
    if isinstance(data, dict):
        for lang, item in data.items():
            if isinstance(item, dict) and isinstance(item.get("semantic"), dict):
                result[lang] = item["semantic"]
    return result


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else 'README.md'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'i18n/languages/'

    semantic = _load_semantic_report()
    try:
        errors, metrics = evaluate_outputs(source, output_dir, semantic)
    except Exception as e:
        print(f"README quality gate could not run: {e}")
        return 1

    header = f"{'lang':<5} {'cjk':>4} {'punct':>5} {'ratio':>7} {'bounds':>15} {'glossary':>9} {'struct':>6} {'semantic':>8}"
    print(header)
    for lang in ("en", "fr", "ru", "fa", "ko"):
        item = metrics.get(lang)
        if not item:
            print(f"{lang:<5} missing")
            continue
        bounds = item.get("length_bounds", [0, 0])
        bounds_text = f"[{bounds[0]}, {bounds[1]}]"
        glossary = item.get("glossary", {})
        semantic_info = item.get("semantic") or {}
        sem = semantic_info.get("average")
        print(
            f"{lang:<5} {item.get('chinese_residue', 0):>4} "
            f"{item.get('chinese_punctuation', 0):>5} "
            f"{item.get('length_ratio', 0):>7.3f} "
            f"{bounds_text:>15} "
            f"{glossary.get('hit_rate', 0):>9.3f} "
            f"{str(item.get('structure_ok', False)):>6} "
            f"{('n/a' if sem is None else f'{sem:.3f}'):>8}"
        )

    if not semantic:
        print("semantic: not run (no readme-quality-report.json from this generation pass)")

    if errors:
        print("README translation validation failed:")
        for error in errors[:20]:
            print(f"  - {error}")
        return 1

    print("README translations passed all quality gates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
