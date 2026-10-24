# IntegrityGuard v1.0.0 Release Checklist

## Repository and legal

- [x] MIT license text and copyright attribution are present.
- [x] Package metadata, public version, and release documentation use 1.0.0.
- [x] Baseline schema 1 and report schema 1 remain unchanged.
- [x] No runtime dependency was added.
- [ ] Review the final diff and commit the approved release-preparation changes.

## Validation

- [x] Run the complete local pytest suite on Windows/Python 3.13.
- [x] Run focused scanner security, CLI, and watch-mode tests locally.
- [x] Compile all package and test modules.
- [x] Build and validate both wheel and source distribution locally.
- [x] Install and exercise the wheel in an isolated local environment.
- [x] Install and exercise the source distribution in an isolated local environment.
- [ ] Rebuild from the final approved commit and compare the artifact inventory.
- [ ] Confirm final `git diff --check` and inspect `git status`.
- [ ] Push the approved commit and require all four GitHub Actions matrix jobs.

## Release gate

- [ ] Review residual risks in `docs/security-model.md`.
- [ ] Confirm no secrets, temporary environments, caches, or unintended build
  artifacts are tracked.
- [ ] Inspect the final wheel and source-distribution file lists.
- [ ] Create annotated tag `v1.0.0` only after the release commit passes CI.
- [ ] Create the GitHub Release from the approved release notes.
- [ ] Attach the locally rebuilt and verified wheel and source distribution if
  binary attachments are part of the release policy.
- [ ] Verify the published tag, release notes, and downloadable artifacts.

PyPI publication is not part of this checklist unless it is separately
approved and a trusted-publishing workflow is designed and reviewed.
