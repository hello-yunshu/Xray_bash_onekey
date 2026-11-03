"""Shared machine-translation backend for the PO and README generators.

Both i18n/tools/translate.py and i18n/tools/translate_readme.py must use the
same model, endpoint, secret name, timeout, retry policy and fallback order.
Keep provider configuration here only; callers own content-specific cleanup.
"""

import os
import re
import time

from deep_translator import GoogleTranslator
from translation_terms import protect_terms, restore_placeholders

MODEL = "qwen-mt-plus"
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
API_KEY_ENV = "AI_API_KEY"

MAX_ATTEMPTS = 5
REQUEST_INTERVAL = 1.0
RETRY_CAP_SECONDS = 30
REQUEST_TIMEOUT_SECONDS = 30.0

CHINESE_RE = re.compile(r'[\u4e00-\u9fff]+')
PLACEHOLDER_TEMPLATE = r'__TERM_{}__'

_last_request_at = 0.0
_client = None
_client_key = None


class TranslationError(Exception):
    pass


def rate_limit():
    """Keep every provider request serial and below the documented limits."""
    global _last_request_at
    now = time.monotonic()
    wait = REQUEST_INTERVAL - (now - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


def retry_sleep(attempt):
    time.sleep(min(RETRY_CAP_SECONDS, REQUEST_INTERVAL * (2 ** attempt)))


def contains_chinese(text):
    return bool(CHINESE_RE.search(text))


def chinese_spans(text):
    return sorted(set(CHINESE_RE.findall(text)))


def get_client():
    global _client, _client_key
    api_key = os.getenv(API_KEY_ENV)
    if not api_key:
        raise TranslationError(f"{API_KEY_ENV} environment variable is not set.")
    if _client is None or _client_key != api_key:
        from openai import OpenAI
        _client = OpenAI(
            api_key=api_key,
            base_url=BASE_URL,
            timeout=REQUEST_TIMEOUT_SECONDS,
            max_retries=0,
        )
        _client_key = api_key
    return _client


def _qwen_request(text, target_lang, terms=None):
    rate_limit()
    options = {"source_lang": "zh", "target_lang": target_lang}
    if terms:
        options["terms"] = terms
    completion = get_client().chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": text}],
        extra_body={"translation_options": options},
    )
    content = completion.choices[0].message.content
    if not content or not content.strip():
        raise TranslationError("Qwen-MT-Plus returned an empty translation")
    return content


def _restore(text, protected):
    missing = []
    for index, term in enumerate(protected):
        if re.search(PLACEHOLDER_TEMPLATE.format(index), text, re.IGNORECASE):
            continue
        # Qwen sometimes drops the placeholder while keeping the term itself
        # (for example "Shell" or "Xray"). Treat that as preserved.
        if term.lower() in text.lower():
            continue
        missing.append(term)
    return restore_placeholders(text, protected).strip(), missing


def _restore_checked(text, protected):
    restored, missing = _restore(text, protected)
    if missing:
        raise TranslationError(f"translation dropped technical terms: {missing}")
    return restored


def qwen_translate(text, target_lang):
    protected_text, protected = protect_terms(text)
    identity_terms = [{"source": term, "target": term} for term in protected]

    base_text = protected_text
    raw = _qwen_request(base_text, target_lang)
    translated, missing = _restore(raw, protected)
    if missing:
        # Qwen sometimes drops the placeholder and translates the term. Ask
        # again with the original text and an identity terminology hint.
        base_text = text
        raw = _qwen_request(base_text, target_lang, terms=identity_terms)
        translated, missing = _restore(raw, protected)
        if missing:
            raise TranslationError(f"translation dropped technical terms: {missing}")

    if not contains_chinese(translated):
        return translated

    # Qwen-MT sometimes leaves a Chinese term untouched (observed with
    # "公网"). Translate the residual span in isolation, then ask for the
    # full text again with the provider's terminology hint.
    residual = chinese_spans(translated)
    terms = []
    for span in residual:
        try:
            term = _qwen_request(span, target_lang).strip()
        except Exception as e:
            print(f"Qwen-MT-Plus residual term lookup failed for {span!r}: {e}", flush=True)
            continue
        if term and not contains_chinese(term):
            terms.append({"source": span, "target": term})
    print(f"Qwen-MT-Plus left Chinese {residual}; retrying with terms={terms}", flush=True)
    if terms:
        repair_terms = terms
        if base_text == text and identity_terms:
            repair_terms = identity_terms + terms
        raw = _qwen_request(base_text, target_lang, terms=repair_terms)
        retried, missing = _restore(raw, protected)
        if missing:
            raise TranslationError(f"translation dropped technical terms: {missing}")
        if not contains_chinese(retried):
            return retried
        translated = retried
    raise TranslationError(f"Qwen-MT-Plus output still contains Chinese: {translated!r}")


def google_translate(text, target_lang):
    protected_text, protected = protect_terms(text)
    rate_limit()
    translator = GoogleTranslator(source='zh-CN', target=target_lang)
    translated = translator.translate(protected_text)
    if translated is None:
        raise TranslationError("Google Translate returned None")
    return _restore_checked(translated, protected)


def translate(text, target_lang, postprocess=None, accept=None):
    """Try Qwen-MT-Plus, then Google, with one shared retry policy.

    ``postprocess`` cleans the raw provider output for the caller's format.
    ``accept`` rejects a candidate that still violates the caller's contract.
    Raises TranslationError when both providers are exhausted.
    """
    if postprocess is None:
        postprocess = lambda value: value.strip()
    if accept is None:
        accept = lambda value: bool(value) and not contains_chinese(value)

    qwen_error = TranslationError(f"{API_KEY_ENV} is not set; skipping Qwen-MT-Plus")
    if os.getenv(API_KEY_ENV):
        for attempt in range(MAX_ATTEMPTS):
            try:
                candidate = postprocess(qwen_translate(text, target_lang))
                if accept(candidate):
                    return candidate
                qwen_error = TranslationError(f"Qwen-MT-Plus output rejected: {candidate!r}")
            except Exception as e:
                qwen_error = e
            print(
                f"Qwen-MT-Plus translation failed (attempt {attempt + 1}/{MAX_ATTEMPTS}): {qwen_error}",
                flush=True,
            )
            if attempt < MAX_ATTEMPTS - 1:
                retry_sleep(attempt)

    google_error = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            candidate = postprocess(google_translate(text, target_lang))
            if accept(candidate):
                return candidate
            google_error = TranslationError(f"Google Translate output rejected: {candidate!r}")
        except Exception as e:
            google_error = e
        print(
            f"Google Translate failed (attempt {attempt + 1}/{MAX_ATTEMPTS}): {google_error}",
            flush=True,
        )
        if attempt < MAX_ATTEMPTS - 1:
            retry_sleep(attempt)

    raise TranslationError(
        f"both translation providers failed for {text!r}: qwen={qwen_error}; google={google_error}"
    )
