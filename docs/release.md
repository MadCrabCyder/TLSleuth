# Release Process

## Checklist

Before pushing a release tag:

- Update `source/TLSleuth.psd1` `ModuleVersion`.
- Update `source/TLSleuth.psd1` `PrivateData.PSData.ReleaseNotes` so it starts with the same version.
- Add a matching `CHANGELOG.md` entry using `## <version> (DD-Mmm-YYYY)`.
- Run `Invoke-Build ValidateReleaseMetadata -ReleaseVersion <version>`.
- Run `Invoke-Build Test`.
- Run `Invoke-Build Build`.
- Confirm the GitHub Actions secret `PSGALLERY_API_KEY` is configured before publishing.

## Release Notes

`Invoke-Build WriteReleaseNotes` validates release metadata and writes `release-notes.md` from the matching `CHANGELOG.md` entry. The tag-driven GitHub workflow uses this task instead of parsing the changelog directly.

## Tag Format

Release tags may use either format:

```text
2.3.3
v2.3.3
```

The numeric portion must match `source/TLSleuth.psd1` `ModuleVersion`.
