"""README translation quality gate and semantic spot-check."""

import json
import os
import re
from collections import Counter

from text_quality import (
    COMMENT_RE,
    FENCE_RE,
    IMAGE_RE,
    INLINE_CODE_RE,
    LINK_TARGET_RE,
    chinese_chars,
    chinese_in_code_blocks,
    chinese_punctuation,
    heading_levels,
    length_ratio,
    paragraph_count,
    placeholders,
    similarity,
    visible_text,
)
from translation_glossary import check as glossary_check
from translation_backend import back_translate

LANGUAGES = ("en", "fr", "ru", "fa", "ko")

EXPECTED_LENGTH_RATIO = {
    "en": 6.0,
    "fr": 7.2,
    "ru": 7.0,
    "fa": 5.5,
    "ko": 3.0,
}
LENGTH_TOLERANCE = 0.35
SEMANTIC_SAMPLE_LIMIT = 5
SEMANTIC_SAMPLE_MIN = 0.25
SEMANTIC_AVG_MIN = 0.35
CHINESE_RE = re.compile(r'[\u4e00-\u9fff]')


def _read(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def _fence_lines(text):
    return [line.strip() for line in text.splitlines() if FENCE_RE.match(line)]


def _inline_code(text):
    return sorted(INLINE_CODE_RE.findall(text))


def _urls(text):
    return sorted(LINK_TARGET_RE.findall(text))


def _images(text):
    return sorted(IMAGE_RE.findall(text))


def _comments(text):
    return sorted(COMMENT_RE.findall(text))


def _line_count(text):
    return len(text.splitlines())


def evaluate_pair(source_text, translated_text, lang, semantic=None):
    errors = []
    metrics = {"language": lang}

    if not translated_text.strip():
        return ["empty output"], metrics

    cjk = chinese_chars(translated_text, include_inline_code=True)
    cjk_punct = chinese_punctuation(translated_text, include_inline_code=True)
    code_cjk = chinese_in_code_blocks(translated_text)
    metrics["chinese_residue"] = len(cjk)
    metrics["chinese_punctuation"] = len(cjk_punct)
    metrics["chinese_in_code_blocks"] = len(code_cjk)
    if cjk:
        errors.append(f"Chinese characters remain: {''.join(sorted(set(cjk)))}")
    if cjk_punct:
        errors.append(f"Chinese punctuation remains: {''.join(sorted(set(cjk_punct)))}")

    structure_ok = True
    if _line_count(translated_text) != _line_count(source_text):
        errors.append(f"line count differs ({_line_count(translated_text)} vs {_line_count(source_text)})")
        structure_ok = False
    if _fence_lines(translated_text) != _fence_lines(source_text):
        errors.append(
            f"fenced code blocks differ ({len(_fence_lines(translated_text))} vs {len(_fence_lines(source_text))})"
        )
        structure_ok = False
    if _inline_code(translated_text) != _inline_code(source_text):
        errors.append("inline code spans differ")
        structure_ok = False
    if _urls(translated_text) != _urls(source_text):
        errors.append("link URLs differ")
        structure_ok = False
    if _images(translated_text) != _images(source_text):
        errors.append("image paths differ")
        structure_ok = False
    if _comments(translated_text) != _comments(source_text):
        errors.append("HTML comments differ")
        structure_ok = False
    if heading_levels(translated_text) != heading_levels(source_text):
        errors.append(
            f"heading levels differ ({heading_levels(translated_text)} vs {heading_levels(source_text)})"
        )
        structure_ok = False
    if paragraph_count(translated_text) != paragraph_count(source_text):
        errors.append(
            f"paragraph count differs ({paragraph_count(translated_text)} vs {paragraph_count(source_text)})"
        )
        structure_ok = False
    if placeholders(translated_text) != placeholders(source_text):
        errors.append("placeholders/variables differ")
        structure_ok = False
    metrics["structure_ok"] = structure_ok
    metrics["paragraphs"] = [paragraph_count(source_text), paragraph_count(translated_text)]
    metrics["heading_levels"] = [heading_levels(source_text), heading_levels(translated_text)]

    ratio = length_ratio(source_text, translated_text)
    expected = EXPECTED_LENGTH_RATIO[lang]
    lower = expected * (1 - LENGTH_TOLERANCE)
    upper = expected * (1 + LENGTH_TOLERANCE)
    metrics["length_ratio"] = round(ratio, 3)
    metrics["length_bounds"] = [round(lower, 3), round(upper, 3)]
    if ratio < lower or ratio > upper:
        errors.append(
            f"length ratio {ratio:.3f} outside [{lower:.3f}, {upper:.3f}] for {lang}"
        )

    glossary = glossary_check(lang, source_text, translated_text)
    metrics["glossary"] = {
        "terms": glossary["terms"],
        "hits": glossary["hits"],
        "hit_rate": round(glossary["hit_rate"], 3),
        "missing": glossary["missing"],
        "forbidden": glossary["forbidden"],
    }
    errors.extend(glossary["errors"])

    if semantic:
        metrics["semantic"] = semantic
        if semantic.get("errors"):
            errors.extend(semantic["errors"])
        samples = semantic.get("samples", [])
        if samples and any(sample.get("score", 0) < SEMANTIC_SAMPLE_MIN for sample in samples):
            errors.append("semantic sample below threshold")
        if samples and semantic.get("average", 0) < SEMANTIC_AVG_MIN:
            errors.append("semantic average below threshold")

    metrics["errors"] = errors
    return errors, metrics


def evaluate_translated_texts(source_text, outputs, semantic_reports=None):
    errors = []
    metrics = {}
    semantic_reports = semantic_reports or {}
    for lang in LANGUAGES:
        text = outputs.get(lang)
        if not text:
            errors.append(f"{lang}: missing output")
            continue
        pair_errors, pair_metrics = evaluate_pair(
            source_text, text, lang, semantic=semantic_reports.get(lang)
        )
        for error in pair_errors:
            errors.append(f"{lang}: {error}")
        metrics[lang] = pair_metrics
    return errors, metrics


def evaluate_outputs(source_path, output_dir, semantic_reports=None):
    try:
        source_text = _read(source_path)
    except OSError as e:
        return [f"cannot read source {source_path}: {e}"], {}

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
        return errors, {}
    return evaluate_translated_texts(source_text, outputs, semantic_reports)


def validate_pair(source_text, translated_text):
    return evaluate_pair(source_text, translated_text, "en")[0]


def validate_outputs(source_path, output_dir):
    return evaluate_outputs(source_path, output_dir)[0]


def language_dir(output_dir, lang):
    normalized = os.path.normpath(output_dir)
    if os.path.basename(normalized) == "languages":
        return os.path.join(normalized, lang)
    return os.path.join(output_dir, "languages", lang)


def _select_samples(source_text, limit=SEMANTIC_SAMPLE_LIMIT):
    lines = source_text.splitlines()
    candidates = []
    in_fence = False
    for index, line in enumerate(lines):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        stripped = line.lstrip()
        if stripped.startswith(("#", "|", "```", "~~~")):
            continue
        if len(CHINESE_RE.findall(line)) >= 30:
            candidates.append((index, line))
    candidates.sort(key=lambda item: len(item[1]), reverse=True)
    return sorted(candidates[:limit], key=lambda item: item[0])


def semantic_check_and_repair(source_text, translated_text, lang, retranslate_line,
                               limit=SEMANTIC_SAMPLE_LIMIT):
    source_lines = source_text.splitlines()
    translated_lines = translated_text.splitlines()
    if len(source_lines) != len(translated_lines):
        return translated_text, {
            "samples": [],
            "average": 0.0,
            "errors": [f"line count differs ({len(translated_lines)} vs {len(source_lines)})"],
        }

    samples = []
    errors = []
    for index, source_line in _select_samples(source_text, limit=limit):
        target_line = translated_lines[index]
        target_prose = visible_text(target_line)
        source_prose = visible_text(source_line)
        try:
            back = back_translate(target_prose, lang)
        except Exception as e:
            errors.append(f"semantic back-translation failed for line {index}: {e}")
            samples.append({"line": index, "source": source_line[:100], "score": 0.0, "error": str(e)})
            continue
        score = similarity(source_prose, back)
        record = {
            "line": index,
            "source": source_prose[:100],
            "back_translation": back[:100],
            "score": round(score, 3),
            "retried": False,
        }
        if score < SEMANTIC_SAMPLE_MIN:
            new_line = retranslate_line(source_line)
            translated_lines[index] = new_line
            back2 = ""
            try:
                back2 = back_translate(visible_text(new_line), lang)
                score2 = similarity(source_prose, back2)
            except Exception as e:
                score2 = 0.0
                errors.append(f"semantic recheck failed for line {index}: {e}")
            record["retried"] = True
            record["score"] = round(score2, 3)
            record["back_translation"] = back2[:100] if score2 else ""
            if score2 < SEMANTIC_SAMPLE_MIN:
                errors.append(
                    f"semantic score {score2:.3f} below {SEMANTIC_SAMPLE_MIN} after retry (line {index})"
                )
        samples.append(record)

    average = (sum(item.get("score", 0.0) for item in samples) / len(samples)) if samples else 0.0
    if samples and average < SEMANTIC_AVG_MIN:
        errors.append(f"semantic average {average:.3f} below {SEMANTIC_AVG_MIN}")
    result = '\n'.join(translated_lines)
    if translated_text.endswith('\n'):
        result += '\n'
    return result, {
        "samples": samples,
        "average": round(average, 3),
        "errors": errors,
    }
