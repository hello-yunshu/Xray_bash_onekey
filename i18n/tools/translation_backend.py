"""Shared machine-translation backend with a configurable provider chain.

Providers:
  - qwen          Qwen-MT-Plus via the OpenAI-compatible DashScope endpoint
  - libretranslate  self-hosted LibreTranslate (optional), never blocked by IP
  - google        legacy fallback, usually rate-limited from CI runners

Configuration is read from the environment so the same code serves the PO and
README generators. No provider is allowed to write a partial file: callers
build every language in memory and only commit after the quality gate passes.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request

from deep_translator import GoogleTranslator
from translation_terms import protect_terms, restore_placeholders

MODEL = "qwen-mt-plus"
BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
API_KEY_ENV = "AI_API_KEY"
LIBRETRANSLATE_URL_ENV = "LIBRETRANSLATE_URL"
LIBRETRANSLATE_KEY_ENV = "LIBRETRANSLATE_API_KEY"

MAX_ATTEMPTS = 5
REQUEST_INTERVAL = 1.0
RETRY_CAP_SECONDS = 30
REQUEST_TIMEOUT_SECONDS = 30.0
CIRCUIT_FAILURE_THRESHOLD = 3
CIRCUIT_COOLDOWN_SECONDS = 60

CHINESE_RE = re.compile(r'[\u4e00-\u9fff]+')
PLACEHOLDER_TEMPLATE = r'__TERM_{}__'

_last_request_at = 0.0
_client = None
_client_key = None


class TranslationError(Exception):
    pass


class ProviderError(TranslationError):
    def __init__(self, provider, kind, message, status=None):
        self.provider = provider
        self.kind = kind
        self.status = status
        self.message = message
        super().__init__(f"{provider} {kind}: {message}")


class CircuitBreaker:
    def __init__(self):
        self.failures = {}
        self.open_until = {}
        self.last_error = {}

    def is_open(self, provider):
        if time.monotonic() >= self.open_until.get(provider, 0):
            if self.failures.get(provider, 0) >= CIRCUIT_FAILURE_THRESHOLD:
                self.failures[provider] = 0
            return False
        return True

    def record_success(self, provider):
        self.failures[provider] = 0
        self.open_until[provider] = 0

    def record_failure(self, provider, error):
        self.last_error[provider] = error
        self.failures[provider] = self.failures.get(provider, 0) + 1
        if self.failures[provider] >= CIRCUIT_FAILURE_THRESHOLD:
            self.open_until[provider] = time.monotonic() + CIRCUIT_COOLDOWN_SECONDS

    def summary(self):
        parts = []
        for provider, until in self.open_until.items():
            remaining = int(until - time.monotonic())
            if remaining > 0:
                parts.append(f"{provider} open for {remaining}s")
        return ", ".join(parts) if parts else "closed"


_breaker = CircuitBreaker()
_force = False


def rate_limit():
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
        raise ProviderError("qwen", "not_configured", f"{API_KEY_ENV} is not set")
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


def _classify(provider, error):
    status = getattr(error, 'status_code', None)
    if isinstance(error, urllib.error.HTTPError):
        status = error.code
    if status in (401, 403):
        kind = "auth"
    elif status == 429:
        kind = "quota"
    elif status and 500 <= status < 600:
        kind = "server"
    elif isinstance(error, (urllib.error.URLError, TimeoutError)):
        kind = "network"
    else:
        name = type(error).__name__.lower()
        kind = "network" if ("timeout" in name or "connection" in name) else "unknown"
    return ProviderError(provider, kind, str(error), status)


def _format_error(error):
    if isinstance(error, ProviderError):
        return f"{error.provider}(kind={error.kind}, status={error.status}, {error.message})"
    return str(error)


def _qwen_request(text, target_lang, terms=None, source_lang="zh"):
    rate_limit()
    options = {"source_lang": source_lang, "target_lang": target_lang}
    if terms:
        options["terms"] = terms
    try:
        completion = get_client().chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": text}],
            extra_body={"translation_options": options},
        )
    except ProviderError:
        raise
    except Exception as e:
        raise _classify("qwen", e)
    content = completion.choices[0].message.content
    if not content or not content.strip():
        raise ProviderError("qwen", "empty", "Qwen-MT-Plus returned an empty translation")
    return content


def _restore(text, protected):
    missing = []
    for index, term in enumerate(protected):
        if re.search(PLACEHOLDER_TEMPLATE.format(index), text, re.IGNORECASE):
            continue
        if term.lower() in text.lower():
            continue
        missing.append(term)
    return restore_placeholders(text, protected).strip(), missing


def _restore_checked(text, protected, provider):
    restored, missing = _restore(text, protected)
    if missing:
        raise ProviderError(provider, "term_missing", f"translation dropped technical terms: {missing}")
    return restored


def _merge_terms(*groups):
    merged = {}
    for group in groups:
        for item in group or []:
            source = item.get("source")
            target = item.get("target")
            if source and target and source not in merged:
                merged[source] = target
    result = [{"source": source, "target": target} for source, target in merged.items()]
    result.sort(key=lambda item: len(item["source"]), reverse=True)
    return result


def _strip_short_residue(source, translated):
    if " " in source.strip() or any(p in source for p in "，。：；、"):
        return translated
    stripped = CHINESE_RE.sub("", translated).strip()
    if stripped and not contains_chinese(stripped):
        return stripped
    return translated


def qwen_translate(text, target_lang, terms=None):
    protected_text, protected = protect_terms(text)
    identity_terms = [{"source": term, "target": term} for term in protected]
    base_terms = _merge_terms(terms or [], identity_terms)

    base_text = protected_text
    raw = _qwen_request(base_text, target_lang, terms=base_terms)
    translated, missing = _restore(raw, protected)
    if missing:
        base_text = text
        raw = _qwen_request(base_text, target_lang, terms=base_terms)
        translated, missing = _restore(raw, protected)
        if missing:
            raise ProviderError("qwen", "term_missing", f"translation dropped technical terms: {missing}")

    if not contains_chinese(translated):
        return translated

    residual = chinese_spans(translated)
    residue_terms = []
    for span in residual:
        try:
            term = _qwen_request(span, target_lang).strip()
        except ProviderError as e:
            print(f"Qwen-MT-Plus residual term lookup failed for {span!r}: {e}", flush=True)
            continue
        term = _strip_short_residue(span, term)
        if term and not contains_chinese(term):
            residue_terms.append({"source": span, "target": term})
    print(f"Qwen-MT-Plus left Chinese {residual}; retrying with terms={residue_terms}", flush=True)
    if residue_terms:
        raw = _qwen_request(base_text, target_lang, terms=_merge_terms(base_terms, residue_terms))
        retried, missing = _restore(raw, protected)
        if missing:
            raise ProviderError("qwen", "term_missing", f"translation dropped technical terms: {missing}")
        if not contains_chinese(retried):
            return retried
        translated = retried
    cleaned = _strip_short_residue(text, translated)
    if cleaned != translated and not contains_chinese(cleaned):
        return cleaned
    raise ProviderError("qwen", "chinese_residue", f"output still contains Chinese: {translated!r}")


def libretranslate_translate(text, target_lang, source_lang="zh"):
    url = os.getenv(LIBRETRANSLATE_URL_ENV)
    if not url:
        raise ProviderError("libretranslate", "not_configured", f"{LIBRETRANSLATE_URL_ENV} is not set")
    endpoint = url.rstrip("/")
    if not endpoint.endswith("/translate"):
        endpoint += "/translate"
    protected_text, protected = protect_terms(text)
    payload = {
        "q": protected_text,
        "source": source_lang,
        "target": target_lang,
        "format": "text",
    }
    api_key = os.getenv(LIBRETRANSLATE_KEY_ENV)
    if api_key:
        payload["api_key"] = api_key
    data = json.dumps(payload).encode('utf-8')
    request = urllib.request.Request(
        endpoint, data=data, headers={"Content-Type": "application/json"}
    )
    rate_limit()
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        raise _classify("libretranslate", e)
    translated = body.get("translatedText") if isinstance(body, dict) else None
    if not translated:
        raise ProviderError("libretranslate", "empty", "LibreTranslate returned an empty translation")
    return _restore_checked(translated, protected, "libretranslate")


def google_translate(text, target_lang):
    protected_text, protected = protect_terms(text)
    rate_limit()
    try:
        translated = GoogleTranslator(source='zh-CN', target=target_lang).translate(protected_text)
    except Exception as e:
        raise _classify("google", e)
    if translated is None:
        raise ProviderError("google", "empty", "Google Translate returned None")
    return _restore_checked(translated, protected, "google")


def _provider_chain():
    chain = os.getenv("TRANSLATION_PROVIDER_CHAIN") or "qwen,libretranslate,google"
    names = [name.strip() for name in chain.split(',') if name.strip()]
    available = []
    skipped = []
    for name in names:
        if name == "qwen":
            if os.getenv(API_KEY_ENV):
                available.append(
                    ("qwen", lambda text, target, terms=None: qwen_translate(text, target, terms=terms))
                )
            else:
                skipped.append("qwen(not configured: AI_API_KEY)")
        elif name == "libretranslate":
            if os.getenv(LIBRETRANSLATE_URL_ENV):
                available.append(
                    ("libretranslate", lambda text, target, terms=None: libretranslate_translate(text, target))
                )
            else:
                skipped.append("libretranslate(not configured: LIBRETRANSLATE_URL)")
        elif name == "google":
            available.append(
                ("google", lambda text, target, terms=None: google_translate(text, target))
            )
        else:
            skipped.append(f"{name}(unknown provider)")
    return available, skipped


def translate(text, target_lang, terms=None, postprocess=None, accept=None):
    if postprocess is None:
        postprocess = lambda value: value.strip()
    if accept is None:
        accept = lambda value: bool(value) and not contains_chinese(value)

    providers, skipped = _provider_chain()
    errors = {}
    for attempt in range(MAX_ATTEMPTS):
        available = [(name, func) for name, func in providers if not _breaker.is_open(name)]
        if not available:
            summary = "; ".join(
                f"{name}(circuit open, last={_format_error(_breaker.last_error.get(name, 'none'))})"
                for name, _ in providers
            )
            skipped_text = f"; skipped=[{'; '.join(skipped)}]" if skipped else ""
            raise TranslationError(
                f"all translation providers are unavailable for {text!r}: {summary}{skipped_text}"
            )
        for name, func in available:
            try:
                candidate = postprocess(func(text, target_lang, terms=terms))
                if accept(candidate):
                    _breaker.record_success(name)
                    return candidate
                raise ProviderError(name, "rejected", f"output rejected by accept(): {candidate!r}")
            except ProviderError as e:
                errors[name] = e
                _breaker.record_failure(name, e)
            except Exception as e:
                wrapped = _classify(name, e)
                errors[name] = wrapped
                _breaker.record_failure(name, wrapped)
        if attempt < MAX_ATTEMPTS - 1:
            retry_sleep(attempt)

    summary = "; ".join(
        f"{name}({_format_error(errors.get(name, 'no attempt'))})" for name, _ in providers
    )
    skipped_text = f"; skipped=[{'; '.join(skipped)}]" if skipped else ""
    raise TranslationError(
        f"all translation providers failed for {text!r}: {summary}{skipped_text}; circuit={_breaker.summary()}"
    )


def back_translate(text, source_lang):
    """Translate a target-language sentence back to Chinese for semantic QA."""
    errors = []
    if os.getenv(API_KEY_ENV) and not _breaker.is_open("qwen"):
        try:
            result = _qwen_request(text, "zh", source_lang=source_lang).strip()
            _breaker.record_success("qwen")
            return result
        except ProviderError as e:
            errors.append(_format_error(e))
            _breaker.record_failure("qwen", e)
    if os.getenv(LIBRETRANSLATE_URL_ENV) and not _breaker.is_open("libretranslate"):
        try:
            result = libretranslate_translate(text, "zh", source_lang=source_lang)
            _breaker.record_success("libretranslate")
            return result
        except ProviderError as e:
            errors.append(_format_error(e))
            _breaker.record_failure("libretranslate", e)
    if not _breaker.is_open("google"):
        try:
            rate_limit()
            result = GoogleTranslator(source=source_lang, target='zh-CN').translate(text)
            if not result:
                raise ProviderError("google", "empty", "Google Translate returned an empty back-translation")
            _breaker.record_success("google")
            return result.strip()
        except Exception as e:
            wrapped = _classify("google", e)
            errors.append(_format_error(wrapped))
            _breaker.record_failure("google", wrapped)
    raise TranslationError(
        "back-translation unavailable: " + "; ".join(errors if errors else ["no provider configured"])
    )
