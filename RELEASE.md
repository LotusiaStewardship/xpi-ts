# Release Process

Releases are cut from `master` by a tracked script, mirroring
`contrib/devtools/release.sh` in `lotusd`:

```bash
./release.sh --bump patch       # 0.4.0 -> 0.4.1
./release.sh --bump minor       # 0.4.0 -> 0.5.0
./release.sh --bump major       # 0.4.0 -> 1.0.0
./release.sh --version 0.4.1    # explicit
./release.sh --current          # tag the version already in package.json
```

`--current` exists because a feature PR may already have bumped
`package.json` (0.4.0 landed that way). For every later release, let the
script own the bump with `--bump` or `--version`.

`--dry-run` validates the plan without writing, committing, tagging or
running the preflight.

## Prerequisites

- On `master`. The script refuses any other branch: a release cut from a
  feature branch would tag a commit that never reached `master`.
- No uncommitted changes to tracked files. Untracked notes are fine.
- `origin` points at the canonical remote (`LotusiaStewardship/xpi-ts`).
- For `--publish`: local `master` must equal `origin/master`, and the npm
  trusted publisher must be configured (see below).

## What the script does

1. Reads the current version from `package.json`.
2. Computes the new version, or applies `--version`, or keeps the current
   one with `--current`.
3. Refuses to continue if `vX.Y.Z` exists locally or on `origin`. Checking
   there rather than at `git tag` avoids leaving an untagged bump commit on
   `master`.
4. Runs the full preflight: `format:check`, `lint`, `test`, `build`, and
   `npm pack --dry-run`.
5. Updates every version-carrying file and fails if any of them does not
   end up carrying the new version.
6. Commits as `Bump version to X.Y.Z` (skipped with `--current`).
7. Tags that commit as annotated `vX.Y.Z` (matching the existing tags).
8. With `--publish`, pushes `master` and **only** that tag to `origin`. It
   does not use `--tags`, which would publish every local tag.

The commit and tag stay local unless `--publish` is given, because the push
is what publishes: the tag triggers `.github/workflows/release.yml`.

## Version-carrying files

| File                | Field                                     | What consumes it                    |
| ------------------- | ----------------------------------------- | ----------------------------------- |
| `package.json`      | `version`                                 | npm package version, `xpi-ts@X.Y.Z` |
| `package-lock.json` | root `version` and `packages[""].version` | `npm ci`, reproducible installs     |

The script updates both with `npm version --no-git-tag-version
--ignore-scripts` and verifies all three fields. Any other changed file
aborts the release. The `version` and `postversion` lifecycle scripts were
removed: `postversion` ran `git push --tags`, which the script deliberately
avoids.

## Publishing

npm publishing uses **trusted publishing** over GitHub Actions OIDC; no
long-lived npm token is stored in the repository or on a laptop.

One-time setup on npmjs.com:

1. Open the `xpi-ts` package settings.
2. Add a trusted publisher: GitHub Actions, organization
   `LotusiaStewardship`, repository `xpi-ts`, workflow filename
   `release.yml`, environment blank.
3. Ensure the package's repository field matches the GitHub repository
   (it does).

Then:

```bash
./release.sh --version 0.4.1 --publish
```

The push runs `.github/workflows/release.yml`, which:

- checks that the tag matches `package.json`;
- installs from the lockfile and runs `format:check`, `lint`, `test`,
  `build`, and `npm pack --dry-run`;
- publishes with `npm publish --provenance --access public`.

No GitHub release is created: the tag and the npm version page are the
record. The job needs `id-token: write` for OIDC. npm CLI 11.5.1 or newer
is required; the workflow uses Node 24.

## Testing the pipeline without publishing

`workflow_dispatch` runs the full verification and pack steps but skips
publish because the ref is not a `v*.*.*` tag. Dispatch it against any
branch or `master` to rehearse.

## If something fails

- **Preflight fails:** nothing was written; fix the tree and rerun.
- **Publish fails after the tag was pushed:** the tag exists but the npm
  version does not. Re-run the workflow for that tag
  (`gh workflow run release.yml --ref vX.Y.Z`) after fixing the cause. If
  the version is already on npm, you cannot republish it; cut the next
  version instead.
- **Tag exists but should not:** delete it
  (`git push origin :vX.Y.Z && git tag -d vX.Y.Z`) only if npm does not
  have that version, then cut it again. A tag on a commit that is not on
  `master` is never a valid release.

## Version rules

Versions are `x.y.z`, numeric only. There are no release candidates or
build suffixes; npm's `latest` dist-tag is the release. The tag and the
tree must agree, and the workflow refuses to publish if they do not.

## Differences from lotusd's cadence

- The artifact is the npm tarball, not platform binaries; there is no
  Docker image, asset manifest or GitHub release.
- `release.sh` does not publish. The tag push triggers the workflow, and
  `--publish` is required to push, so a local cut cannot publish by
  accident.
- `--current` exists for pre-bumped versions; lotusd's tree is always
  bumped by its script.
