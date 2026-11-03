"""Fail the translation workflow when a README output is incomplete."""

import sys

from readme_validation import validate_outputs


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else 'README.md'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'i18n/languages/'

    errors = validate_outputs(source, output_dir)
    if errors:
        print("README translation validation failed:")
        for error in errors[:20]:
            print(f"  - {error}")
        return 1

    print("README translations are structurally complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
