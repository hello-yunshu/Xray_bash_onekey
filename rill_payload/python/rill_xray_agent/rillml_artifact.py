"""RillML prebuilt ``rill-runtime`` artifact resolver and consumption layer.

Downstream policy (read-only consumption, never rebuild):

  - Only the upstream ``hello-yunshu/rill-ml`` signed release index is trusted.
  - Platform selection is deterministic and fail-closed: unknown OS / CPU / libc
    never silently selects a wrong-ABI binary.
  - Only ``channel == stable``, matching OS+arch, matching libc artifact id
    (``rill-runtime`` = GNU/glibc, ``rill-runtime-musl`` = musl) and a compatible
    ``runtimeApiVersion`` is selected.
  - The index Ed25519 signature is verified (pure stdlib, see rillml_ed25519).
  - Every downloaded asset is re-verified by size + SHA-256; a mismatch fails
    closed and never activates.
  - Activation is atomic with a previous-good ``rollback`` preserved; a failed
    probe never replaces the current runtime.
  - No Cargo / cargo-zigbuild / cross-compile happens here, ever.

Production keeps RillML inactive (``nativeRuntimeSupported=false`` /
``supportedRuntime=portable-python``); this module makes the capability
available and fully testable without enabling it.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .canonical import atomic_write_bytes, canonical_bytes, read_json
from . import rillml_ed25519

# --- upstream release contract (may be overridden for tests / mirror) ---
STABLE_INDEX_URL = (
    'https://github.com/hello-yunshu/rill-ml/releases/download/'
    'local-ai-stable/stable-index.json'
)
CANDIDATE_INDEX_URL = (
    'https://github.com/hello-yunshu/rill-ml/releases/download/'
    'local-ai-candidate/candidate-index.json'
)
DEFAULT_PUBLISHER_KEY_ID = 'rillml-examples-2026-001'
DEFAULT_PUBLIC_KEY_HEX = (
    '29fd1fc2f22bd7e405aec167ff0a0d8de'
    '791f011c415075d4c5f9f64fd93fc2e'
)
INDEX_SCHEMA_VERSION = 2
SUPPORTED_API_VERSION = 2
RUNTIME_ID_GNU = 'rill-runtime'
RUNTIME_ID_MUSL = 'rill-runtime-musl'
MODEL_ARTIFACT_ID = 'rillml.example.default'
HANDLER_ARTIFACT_ID = 'rillml.echo.handler'

# --- bounds / security ---
MAX_INDEX_BYTES = 512 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_IPC_LINE_BYTES = 1024 * 1024
FORBIDDEN_URL_SCHEMES = frozenset({'file', 'data', 'javascript', 'ftp', 'blob'})
LOCALHOST_HOSTS = frozenset({'localhost', '127.0.0.1', '::1', '0.0.0.0'})
SHA256_RE = re.compile(r'^[a-f0-9]{64}$')
ID_RE = re.compile(r'^[A-Za-z0-9._-]{1,128}$')

# Normalize the common aliases so selection never depends on a runner's naming.
_ARCH_NORMALIZE = {
    'x86_64': 'x86_64', 'amd64': 'x86_64', 'x64': 'x86_64',
    'aarch64': 'aarch64', 'arm64': 'aarch64',
}
_OS_MAP = {'linux': 'linux', 'darwin': 'macos', 'win32': 'windows'}
_MUSL_LOADERS = (
    '/lib/ld-musl-x86_64.so.1', '/lib/ld-musl-aarch64.so.1',
    '/lib/ld-musl-armhf.so.1',
)
_GLIBC_LOADERS = (
    '/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
    '/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1',
)


class RillMLError(Exception):
    """Base error for RillML artifact consumption failures."""


class RillMLUnsupported(RillMLError):
    """Platform or release channel has no usable prebuilt artifact (fail-closed)."""


class RillMLValidationError(RillMLError):
    """Index / artifact metadata or checksum/signature verification failed."""


class RillMLDownloadError(RillMLError):
    """Artifact could not be fetched."""


class RillMLProbeError(RillMLError):
    """Runtime binary did not pass startup / IPC handshake compatibility."""


def _validate_https_url(url, *, allow_localhost=False):
    """Strict HTTPS-only URL policy for anything fetched from the index."""
    if not isinstance(url, str) or not url:
        raise RillMLValidationError('artifact URL must be a non-empty string')
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() in FORBIDDEN_URL_SCHEMES:
        raise RillMLValidationError(f'forbidden URL scheme: {url!r}')
    if parsed.scheme != 'https':
        raise RillMLValidationError(f'artifact URL must use https: {url!r}')
    if not parsed.hostname:
        raise RillMLValidationError(f'artifact URL must have a host: {url!r}')
    if parsed.username or parsed.password:
        raise RillMLValidationError(f'artifact URL must not embed credentials: {url!r}')
    if parsed.fragment:
        raise RillMLValidationError(f'artifact URL must not contain a fragment: {url!r}')
    host = parsed.hostname.lower().strip('[]')
    if host in LOCALHOST_HOSTS and not allow_localhost:
        raise RillMLValidationError(f'artifact URL must not point at localhost: {url!r}')


def detect_platform():
    """Deterministic, fail-closed host identity -> {'os','arch','libc'}.

    Raises :class:`RillMLUnsupported` when any component is unknown or (on
    Linux) the libc/ABI cannot be positively identified - never guesses.
    """
    osname = _OS_MAP.get(sys.platform)
    if osname is None:
        raise RillMLUnsupported(f'unsupported OS platform: {sys.platform!r}')
    machine = platform.machine().lower()
    arch = _ARCH_NORMALIZE.get(machine)
    if arch is None:
        raise RillMLUnsupported(f'unsupported CPU architecture: {machine!r}')
    libc = None
    if osname == 'linux':
        libc = _detect_linux_libc()
        if libc is None:
            raise RillMLUnsupported(
                'unable to positively identify Linux libc (glibc vs musl); '
                'failing closed rather than guessing an ABI')
    return {'os': osname, 'arch': arch, 'libc': libc}


def _detect_linux_libc():
    """Return 'gnu' | 'musl' | None. Evidence-based only; None means unknown."""
    try:
        result = subprocess.run(
            ['ldd', '--version'], capture_output=True, text=True, timeout=5)
        combined = (result.stdout + result.stderr).lower()
        if 'musl' in combined:
            return 'musl'
        if 'glibc' in combined:
            return 'gnu'
    except (OSError, subprocess.SubprocessError):
        pass
    if os.path.exists('/etc/alpine-release'):
        return 'musl'
    if any(os.path.exists(c) for c in _MUSL_LOADERS):
        return 'musl'
    if any(os.path.exists(c) for c in _GLIBC_LOADERS):
        return 'gnu'
    return None


def canonical_index_bytes(payload):
    """Canonical JSON (sorted keys, compact) - matches the upstream signer."""
    return canonical_bytes(payload)


def parse_release_index(text, *, trusted_key_id=None, public_key_hex=None,
                        channel='stable'):
    """Parse and cryptographically verify a signed RillML release index.

    Returns the verified ``payload`` dict. Fails closed on malformed JSON,
    missing/malformed signature, Ed25519 mismatch, unknown publisher, schema
    version mismatch or an unexpected release channel.
    """
    try:
        envelope = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise RillMLValidationError(f'release index is not valid JSON: {exc}') from exc
    if not isinstance(envelope, dict):
        raise RillMLValidationError('release index envelope must be an object')
    payload = envelope.get('payload')
    signature = envelope.get('signature')
    if not isinstance(payload, dict):
        raise RillMLValidationError('release index payload missing or invalid')
    if not isinstance(signature, str):
        raise RillMLValidationError('release index signature missing or invalid')
    key_id = trusted_key_id or DEFAULT_PUBLISHER_KEY_ID
    pub_hex = public_key_hex or DEFAULT_PUBLIC_KEY_HEX
    if not rillml_ed25519.verify_hex(pub_hex, canonical_index_bytes(payload), signature):
        raise RillMLValidationError('release index Ed25519 signature verification failed')
    if payload.get('schemaVersion') != INDEX_SCHEMA_VERSION:
        raise RillMLValidationError(
            f'release index schemaVersion {payload.get("schemaVersion")!r} '
            f'!= expected {INDEX_SCHEMA_VERSION}')
    if payload.get('publisherKeyId') != key_id:
        raise RillMLValidationError(
            f'release index publisherKeyId {payload.get("publisherKeyId")!r} '
            f'!= trusted {key_id!r}')
    if channel and payload.get('channel') != channel:
        raise RillMLValidationError(
            f'release index channel {payload.get("channel")!r} != required {channel!r}')
    artifacts = payload.get('artifacts')
    if not isinstance(artifacts, list) or not artifacts:
        raise RillMLValidationError('release index has no artifacts')
    for artifact in artifacts:
        _validate_artifact_shape(artifact)
    return payload


_ARTIFACT_COMMON_FIELDS = ('kind', 'id', 'version', 'url', 'sha256')


def _validate_artifact_shape(artifact):
    if not isinstance(artifact, dict):
        raise RillMLValidationError('artifact entry must be an object')
    kind = artifact.get('kind')
    if kind not in ('runtime', 'model', 'handler'):
        raise RillMLValidationError(f'unknown artifact kind {artifact.get("kind")!r}')
    # Common fields every artifact kind must carry.
    for key in _ARTIFACT_COMMON_FIELDS:
        value = artifact.get(key)
        if not isinstance(value, str) or not value:
            raise RillMLValidationError(f'artifact missing/invalid field {key!r}')
    if not SHA256_RE.match(artifact['sha256']):
        raise RillMLValidationError('artifact sha256 must be 64 lowercase hex chars')
    if artifact['version'].count('.') < 2:
        raise RillMLValidationError(f'invalid artifact version {artifact["version"]!r}')
    if not isinstance(artifact.get('runtimeApiVersion'), int):
        raise RillMLValidationError('artifact runtimeApiVersion must be an integer')
    if not isinstance(artifact.get('size'), int) or artifact['size'] < 0:
        raise RillMLValidationError('artifact size must be a non-negative integer')
    _validate_https_url(artifact['url'])
    # Kind-specific fields: only runtime artifacts are platform-bound; model /
    # handler entries in the real stable index carry no targetOs/targetArch.
    if kind == 'runtime':
        for key in ('targetOs', 'targetArch'):
            value = artifact.get(key)
            if not isinstance(value, str) or not value:
                raise RillMLValidationError(
                    f'runtime artifact missing/invalid field {key!r}')
    elif kind == 'handler':
        if not isinstance(artifact.get('handlerApiVersion'), int):
            raise RillMLValidationError(
                'handler artifact handlerApiVersion must be an integer')
        if not isinstance(artifact.get('minRuntimeVersion'), str) or not artifact[
                'minRuntimeVersion']:
            raise RillMLValidationError(
                'handler artifact missing/invalid minRuntimeVersion')


def runtime_artifact_id(libc):
    """Map a detected libc/ABI to the stable artifact id used by the index."""
    return RUNTIME_ID_MUSL if libc == 'musl' else RUNTIME_ID_GNU


def select_runtime_artifact(payload, *, target_os, target_arch, libc,
                            api_version=SUPPORTED_API_VERSION, channel='stable'):
    """Deterministically select the single matching prebuilt runtime artifact.

    Raises :class:`RillMLValidationError` (never guesses) on a wrong channel,
    wrong OS/arch/libc, incompatible API or ambiguous/missing match.
    """
    if channel and payload.get('channel') != channel:
        raise RillMLValidationError(
            f'release channel {payload.get("channel")!r} != required {channel!r}')
    wanted_id = runtime_artifact_id(libc)
    matches = []
    reasons = []
    for artifact in payload.get('artifacts', []):
        if artifact.get('kind') != 'runtime':
            continue
        if artifact.get('targetOs') != target_os:
            reasons.append(f'os={artifact.get("targetOs")}')
            continue
        if artifact.get('targetArch') != target_arch:
            reasons.append(f'arch={artifact.get("targetArch")}')
            continue
        if artifact.get('id') != wanted_id:
            reasons.append(f'libc/ABI={artifact.get("id")}')
            continue
        api = artifact.get('runtimeApiVersion')
        if api != api_version:
            reasons.append(f'runtimeApiVersion={api}')
            continue
        matches.append(artifact)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise RillMLValidationError(
            f'ambiguous runtime artifact match (n={len(matches)})')
    raise RillMLValidationError(
        f'no supported prebuilt rill-runtime for os={target_os} arch={target_arch} '
        f'libc={libc} apiVersion={api_version}; rejected candidates: {reasons[:8]}')


def select_named_artifact(payload, *, kind, artifact_id, version=None):
    """Select exactly one artifact by kind + stable id (model/handler)."""
    matches = [a for a in payload.get('artifacts', [])
               if a.get('kind') == kind and a.get('id') == artifact_id
               and (version is None or a.get('version') == version)]
    if len(matches) != 1:
        raise RillMLValidationError(
            f'expected exactly one {kind} artifact id={artifact_id!r}; found '
            f'{len(matches)}')
    return matches[0]


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def verify_artifact_file(artifact, path):
    """Re-verify a downloaded artifact against the index (size + SHA-256)."""
    expected_size = artifact['size']
    expected_sha = artifact['sha256']
    path = Path(path)
    actual_size = path.stat().st_size
    if actual_size != expected_size:
        raise RillMLValidationError(
            f'{path.name}: size mismatch (expected {expected_size}, got {actual_size})')
    actual_sha = sha256_file(path)
    if actual_sha.lower() != expected_sha.lower():
        raise RillMLValidationError(
            f'{path.name}: SHA-256 mismatch (expected {expected_sha}, got {actual_sha})')
    return actual_sha


def _http_get(url, *, timeout, attempts, max_bytes):
    _validate_https_url(url)
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(
                url, headers={'User-Agent': 'rill-xray-agent/1.0'})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                _validate_https_url(response.geturl())
                data = response.read()
                if len(data) > max_bytes:
                    raise RillMLDownloadError(
                        f'response too large ({len(data)} > {max_bytes} bytes)')
                return data
        except (urllib.error.URLError, TimeoutError, RillMLDownloadError) as exc:
            if attempt == attempts:
                raise RillMLDownloadError(f'fetch failed for {url!r}: {exc}') from exc
            time.sleep(min(2 ** (attempt - 1), 8))
    raise RillMLDownloadError(f'fetch failed for {url!r}')


def fetch_release_index(index_url=None, *, timeout=60.0, attempts=4):
    """Fetch the (signed) release index bytes over HTTPS."""
    url = index_url or os.environ.get(
        'RILLML_INDEX_URL', STABLE_INDEX_URL)
    return _http_get(url, timeout=timeout, attempts=attempts,
                     max_bytes=MAX_INDEX_BYTES)


def download_artifact(artifact, dest_dir, *, timeout=60.0, attempts=4):
    """Download + re-verify an artifact; returns the local Path (executable)."""
    url = artifact['url']
    _validate_https_url(url)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    name = urllib.parse.urlparse(url).path.rstrip('/').rsplit('/', 1)[-1]
    if not name or name in ('.', '..'):
        raise RillMLValidationError(f'artifact URL has no usable filename: {url!r}')
    target = dest / name
    if target.is_symlink():
        raise RillMLValidationError(f'staging path is a symlink: {target}')
    data = _http_get(url, timeout=timeout, attempts=attempts,
                     max_bytes=MAX_ARTIFACT_BYTES)
    atomic_write_bytes(target, data, 0o750)
    verify_artifact_file(artifact, target)
    return target


def _ipc_call(process, request, *, timeout):
    """Send one NDJSON request, read one bounded response line."""
    line = json.dumps(request, separators=(',', ':')) + '\n'
    if process.stdin is None or process.stdout is None:
        raise RillMLProbeError('runtime IPC streams unavailable')
    process.stdin.write(line.encode('utf-8'))
    process.stdin.flush()
    raw = process.stdout.readline()
    if not raw:
        stderr = ''
        if process.poll() is not None and process.stderr is not None:
            stderr = process.stderr.read().decode('utf-8', errors='replace')[:512]
        raise RillMLProbeError(
            f'runtime closed stdout after {request.get("method")!r}; '
            f'stderr={stderr!r}')
    if len(raw) > MAX_IPC_LINE_BYTES:
        raise RillMLProbeError('runtime response exceeds IPC line bound')
    try:
        return json.loads(raw.decode('utf-8'))
    except ValueError as exc:
        raise RillMLProbeError(f'runtime returned invalid JSON: {exc}') from exc


def probe_runtime(runtime_path, *, expected_version=None, model_path=None,
                  handler_path=None, trusted_key_id=None, public_key_hex=None,
                  timeout=30.0):
    """Startup / compatibility probe for a staged rill-runtime binary.

    ``model_path`` + ``handler_path`` select the full v2 IPC handshake + health
    check; otherwise a lightweight ``--help`` execution check is performed.
    Returns a structured result dict. Raises :class:`RillMLProbeError` on any
    incompatibility so a bad candidate never replaces the current runtime.
    """
    runtime_path = Path(runtime_path)
    if not runtime_path.is_file():
        raise RillMLProbeError(f'runtime binary missing: {runtime_path}')
    if not os.access(runtime_path, os.X_OK):
        raise RillMLProbeError(f'runtime binary is not executable: {runtime_path}')
    key_id = trusted_key_id or DEFAULT_PUBLISHER_KEY_ID
    pub_hex = public_key_hex or DEFAULT_PUBLIC_KEY_HEX
    if model_path and handler_path:
        command = [str(runtime_path), 'serve',
                   '--pack', str(model_path),
                   '--model-trust-key', f'{key_id}={pub_hex}',
                   '--handler', str(handler_path),
                   '--handler-trust-key', f'{key_id}={pub_hex}']
    else:
        command = [str(runtime_path), '--help']
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0)
    except OSError as exc:
        raise RillMLProbeError(f'failed to execute runtime: {exc}') from exc
    try:
        if model_path and handler_path:
            handshake = _ipc_call(process, {
                'method': 'handshake',
                'requestId': 'rillml-probe-handshake',
                'apiVersion': SUPPORTED_API_VERSION,
                'clientName': 'rill-xray-agent',
                'clientVersion': '1.0.0',
            }, timeout=timeout)
            capabilities = handshake.get('effectiveCapabilities')
            checks = {
                'kind': handshake.get('kind') == 'handshake',
                'requestId': handshake.get('requestId') == 'rillml-probe-handshake',
                'apiVersion': handshake.get('apiVersion') == SUPPORTED_API_VERSION,
                'runtimeVersion': (
                    expected_version is None
                    or handshake.get('runtimeVersion') == expected_version),
                'modelPackVersion': (
                    expected_version is None
                    or handshake.get('modelPackVersion') == expected_version),
                'handlerVersion': (
                    expected_version is None
                    or handshake.get('handlerVersion') == expected_version),
                'capabilities': isinstance(capabilities, list) and bool(capabilities),
            }
            if not all(checks.values()):
                raise RillMLProbeError(
                    f'IPC handshake incompatible: {json.dumps(handshake, sort_keys=True)}')
            health = _ipc_call(process, {
                'method': 'health', 'requestId': 'rillml-probe-health',
                'apiVersion': SUPPORTED_API_VERSION,
            }, timeout=timeout)
            if health.get('kind') != 'health' or health.get('healthy') is not True:
                raise RillMLProbeError(
                    f'runtime health probe failed: {json.dumps(health, sort_keys=True)}')
            return {
                'probe': 'handshake',
                'executes': True,
                'runtimeVersion': handshake.get('runtimeVersion'),
                'modelPackId': handshake.get('modelPackId'),
                'handlerId': handshake.get('handlerId'),
                'effectiveCapabilities': capabilities,
                'checks': checks,
            }
        out, err = process.communicate(timeout=timeout)
        if process.returncode != 0:
            raise RillMLProbeError(
                f'runtime --help exited {process.returncode}: '
                f'{err.decode("utf-8", errors="replace")[:256]!r}')
        return {'probe': 'lightweight', 'executes': True, 'exitCode': 0}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


class RillMLRuntimeManager:
    """Staging / current / rollback lifecycle for the prebuilt runtime.

    Layout under ``root``:
      staging/    downloaded but not yet verified/activated assets
      current/    the active verified runtime binary (``rill-runtime``)
      rollback/   the previous-good binary preserved by the last activation
      state.json  atomic activation metadata (version, artifact, probe result)

    All mutations are atomic; a failed probe or verification never touches
    ``current``. If the platform has no supported upstream artifact the manager
    stays deterministically unavailable (never compiles, never guesses).
    """

    def __init__(self, root, *, index_url=None, public_key_hex=None,
                 trusted_key_id=None, channel='stable', api_version=SUPPORTED_API_VERSION):
        self.root = Path(root)
        self.index_url = index_url or os.environ.get(
            'RILLML_INDEX_URL', STABLE_INDEX_URL)
        self.public_key_hex = public_key_hex or DEFAULT_PUBLIC_KEY_HEX
        self.trusted_key_id = trusted_key_id or DEFAULT_PUBLISHER_KEY_ID
        self.channel = channel
        self.api_version = api_version
        self.staging_dir = self.root / 'staging'
        self.current_dir = self.root / 'current'
        self.rollback_dir = self.root / 'rollback'
        self.state_path = self.root / 'state.json'

    def _read_state(self):
        try:
            state = read_json(self.state_path)
            return state if isinstance(state, dict) else {}
        except Exception:
            return {}

    def _write_state(self, state):
        atomic_write_bytes(self.state_path, canonical_bytes(state) + b'\n', 0o600)

    def _current_binary(self):
        return self.current_dir / 'rill-runtime'

    def status(self):
        """Local state + platform identity. Never touches the network."""
        try:
            platform_ = detect_platform()
        except RillMLUnsupported as exc:
            return {
                'schemaVersion': 1, 'supported': False, 'platform': None,
                'channel': self.channel,
                'requiredApiVersion': self.api_version,
                'available': False,
                'unavailableReason': str(exc),
                'current': None, 'rollback': None,
            }
        state = self._read_state()
        current_bin = self._current_binary()
        current = None
        if state.get('version') and current_bin.is_file():
            current = {
                'version': state.get('version'),
                'artifactId': state.get('artifactId'),
                'path': str(current_bin),
                'activatedAtEpochSeconds': state.get('activatedAtEpochSeconds'),
                'probe': state.get('probe'),
            }
        rollback_bin = self.rollback_dir / 'rill-runtime'
        rollback = None
        if state.get('rollbackVersion') and rollback_bin.is_file():
            rollback = {
                'version': state.get('rollbackVersion'),
                'artifactId': state.get('rollbackArtifactId'),
                'path': str(rollback_bin),
            }
        return {
            'schemaVersion': 1, 'supported': True, 'platform': platform_,
            'channel': self.channel, 'requiredApiVersion': self.api_version,
            'available': current is not None,
            'unavailableReason': None,
            'current': current, 'rollback': rollback,
        }

    def resolve(self, *, timeout=60.0, attempts=4):
        """Read + verify the signed index and select this host's artifact.

        Read-only: downloads nothing, mutates nothing. Returns the selected
        artifact plus the verified index metadata.
        """
        platform_ = detect_platform()
        text = fetch_release_index(self.index_url, timeout=timeout, attempts=attempts)
        payload = parse_release_index(
            text.decode('utf-8'), trusted_key_id=self.trusted_key_id,
            public_key_hex=self.public_key_hex, channel=self.channel)
        artifact = select_runtime_artifact(
            payload, target_os=platform_['os'], target_arch=platform_['arch'],
            libc=platform_['libc'], api_version=self.api_version,
            channel=self.channel)
        return {
            'platform': platform_,
            'indexUrl': self.index_url,
            'channel': payload.get('channel'),
            'publisherKeyId': payload.get('publisherKeyId'),
            'version': artifact['version'],
            'artifact': artifact,
        }

    def install(self, *, probe='lightweight', timeout=60.0, attempts=4):
        """Stage, verify, probe and atomically activate the current runtime.

        ``probe='handshake'`` additionally fetches the matching model + handler
        packs from the same signed index and performs a full v2 IPC handshake +
        health check before activation. On any failure the previous-good
        ``current`` (if any) is preserved untouched.
        """
        platform_ = detect_platform()
        resolved = self.resolve(timeout=timeout, attempts=attempts)
        artifact = resolved['artifact']
        payload = resolved.get('payload')
        staged = download_artifact(artifact, self.staging_dir,
                                   timeout=timeout, attempts=attempts)
        model_path = handler_path = None
        if probe == 'handshake':
            if payload is None:
                text = fetch_release_index(self.index_url, timeout=timeout,
                                           attempts=attempts)
                payload = parse_release_index(
                    text.decode('utf-8'), trusted_key_id=self.trusted_key_id,
                    public_key_hex=self.public_key_hex, channel=self.channel)
            model = select_named_artifact(
                payload, kind='model', artifact_id=MODEL_ARTIFACT_ID,
                version=artifact['version'])
            handler = select_named_artifact(
                payload, kind='handler', artifact_id=HANDLER_ARTIFACT_ID,
                version=artifact['version'])
            model_path = download_artifact(model, self.staging_dir,
                                           timeout=timeout, attempts=attempts)
            handler_path = download_artifact(handler, self.staging_dir,
                                             timeout=timeout, attempts=attempts)
        probe_result = probe_runtime(
            staged, expected_version=artifact['version'],
            model_path=model_path, handler_path=handler_path,
            trusted_key_id=self.trusted_key_id,
            public_key_hex=self.public_key_hex)
        self._activate(artifact, staged, probe_result)
        return {'activated': True, 'status': self.status(), 'probe': probe_result}

    def _activate(self, artifact, staged, probe_result):
        self.root.mkdir(parents=True, exist_ok=True)
        current_bin = self._current_binary()
        rollback_bin = self.rollback_dir / 'rill-runtime'
        # Never follow or create symlinks in the managed tree.
        for path in (self.current_dir, self.rollback_dir):
            if path.is_symlink():
                raise RillMLValidationError(f'managed path is a symlink: {path}')
        # Preserve the current binary as the rollback (previous-good).
        if current_bin.is_file() and not current_bin.is_symlink():
            self.rollback_dir.mkdir(parents=True, exist_ok=True)
            if rollback_bin.exists() or rollback_bin.is_symlink():
                rollback_bin.unlink()
            os.replace(current_bin, rollback_bin)
        # Move the staged verified binary into place atomically.
        self.current_dir.mkdir(parents=True, exist_ok=True)
        os.replace(staged, current_bin)
        state = self._read_state()
        state.update({
            'version': artifact['version'],
            'artifactId': artifact.get('id'),
            'activatedAtEpochSeconds': int(time.time()),
            'probe': probe_result,
            'rollbackVersion': state.get('version'),
            'rollbackArtifactId': state.get('artifactId'),
        })
        self._write_state(state)

    def rollback(self):
        """Restore the previous-good runtime into ``current`` (if present)."""
        rollback_bin = self.rollback_dir / 'rill-runtime'
        if not rollback_bin.is_file() or rollback_bin.is_symlink():
            raise RillMLUnsupported('no previous-good runtime available to restore')
        state = self._read_state()
        current_bin = self._current_binary()
        if current_bin.is_file() and not current_bin.is_symlink():
            current_bin.unlink()
        self.current_dir.mkdir(parents=True, exist_ok=True)
        os.replace(rollback_bin, current_bin)
        state.update({
            'version': state.get('rollbackVersion'),
            'artifactId': state.get('rollbackArtifactId'),
            'rollbackVersion': None,
            'rollbackArtifactId': None,
        })
        self._write_state(state)
        return {'rolledBack': True, 'status': self.status()}
