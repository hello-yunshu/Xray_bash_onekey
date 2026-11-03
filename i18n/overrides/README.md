# Translation overrides

Human-reviewed sentences can be pinned here. The translation scripts read
these files before the cache and before any machine provider.

## Layout

```
i18n/overrides/readme/<lang>.json   # README sentences
i18n/overrides/po/<lang>.json       # install.sh gettext msgids
```

Languages: `en`, `fr`, `ru`, `fa`, `ko`.

## Format

```json
{
  "源句子": "人工校对后的译文"
}
```

- The key must match the source string exactly (after Markdown parsing for
  README lines; the raw `msgid` for PO entries).
- Overrides are never rewritten by the workflow. When the source sentence
  changes, the key no longer matches and the old entry stays in the file for
  a human to update; unchanged sentences keep using their override.
- Overrides still go through the glossary, Chinese-residue, structure and
  semantic quality gates. A bad override fails the run instead of being
  silently published.
- Adding or editing an override is a JSON-only change; no code change is
  required.
