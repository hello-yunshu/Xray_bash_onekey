import enum, os
from pathlib import Path
from .canonical import read_json
from .errors import ContractError

# Manifest is provisioned root-owned (0o640) and is read-only at runtime; the
# agent never writes it. Missing, unreadable or corrupt manifests fail closed
# to the locked default (SUPPORTED_LOCKED) below.
DEFAULT_RELEASE_CAPABILITIES_PATH = Path('/opt/rill-xray-agent/share/release-capabilities.json')
RELEASE_CAPABILITY_FEATURES = ('routeAssist', 'boundedAuto')


class ReleaseCapabilityStatus(enum.Enum):
    UNSUPPORTED = 'unsupported'
    SUPPORTED_LOCKED = 'supported_locked'
    AVAILABLE_DISABLED = 'available_disabled'
    AVAILABLE_ENABLED = 'available_enabled'


def _default_entry():
    return {'supported': True, 'released': False}


class ReleaseCapabilities:
    def __init__(self, path=None):
        if path is None:
            path = os.environ.get('RILL_RELEASE_CAPABILITIES_PATH', DEFAULT_RELEASE_CAPABILITIES_PATH)
        self.path = Path(path)
        self._manifest = self._load()

    def _load(self):
        manifest = {f: _default_entry() for f in RELEASE_CAPABILITY_FEATURES}
        try:
            data = read_json(self.path)
        except Exception:
            return manifest
        if not isinstance(data, dict) or data.get('schemaVersion') != 1:
            return manifest
        features = data.get('features')
        if not isinstance(features, dict):
            return manifest
        for f in RELEASE_CAPABILITY_FEATURES:
            entry = features.get(f)
            if not isinstance(entry, dict):
                continue
            for key in ('supported', 'released'):
                if isinstance(entry.get(key), bool):
                    manifest[f][key] = entry[key]
        return manifest

    def _entry(self, feature):
        e = self._manifest.get(feature)
        return e if isinstance(e, dict) else _default_entry()

    def is_supported(self, feature):
        return bool(self._entry(feature).get('supported', True))

    def is_released(self, feature):
        return bool(self._entry(feature).get('released', False))

    def evaluate(self, feature, configured_stage):
        if not self.is_supported(feature):
            return ReleaseCapabilityStatus.UNSUPPORTED
        if not self.is_released(feature):
            return ReleaseCapabilityStatus.SUPPORTED_LOCKED
        if feature == 'routeAssist':
            enabled = configured_stage in ('assist', 'auto')
        elif feature == 'boundedAuto':
            enabled = configured_stage == 'auto'
        else:
            enabled = False
        if enabled:
            return ReleaseCapabilityStatus.AVAILABLE_ENABLED
        return ReleaseCapabilityStatus.AVAILABLE_DISABLED

    def releaseCapabilities(self, configured_stage=None):
        return {'schemaVersion': 1,
                'features': {f: {'supported': self.is_supported(f),
                                 'released': self.is_released(f),
                                 'status': self.evaluate(f, configured_stage).value}
                             for f in RELEASE_CAPABILITY_FEATURES}}

    def with_released(self, feature, value):
        if feature not in RELEASE_CAPABILITY_FEATURES:
            raise ContractError(f'unknown release capability feature: {feature}')
        manifest = {f: dict(e) for f, e in self._manifest.items()}
        manifest[feature]['released'] = bool(value)
        return ReleaseCapabilities._from_manifest(self.path, manifest)

    @classmethod
    def _from_manifest(cls, path, manifest):
        obj = cls.__new__(cls)
        obj.path = Path(path)
        obj._manifest = manifest
        return obj
