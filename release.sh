#!/usr/bin/env bash
#
# Cut a release: bump the package version, commit it, tag it, and optionally
# push the tag so GitHub Actions publishes to npm.
#
# This mirrors contrib/devtools/release.sh in lotusd: master only, clean
# tracked tree, refusal to reuse a tag, every version-carrying file updated
# and verified, a "Bump version to X.Y.Z" commit, an annotated vX.Y.Z tag,
# and only that tag pushed -- never `git push --tags`.
#
# npm publishing runs in .github/workflows/release.yml through trusted
# publishing (OIDC). `--publish` is the switch that pushes and therefore
# publishes; without it the commit and tag stay local for review.

export LC_ALL=C

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  ./release.sh --bump patch|minor|major [--publish] [--dry-run]
  ./release.sh --version x.y.z          [--publish] [--dry-run]
  ./release.sh --current                [--publish] [--dry-run]

Cuts a release from master.

  --bump patch|minor|major  Bump the current package version
  --version x.y.z           Set an explicit version
  --current                 Release the version already in package.json,
                            without a bump commit (for a pre-bumped tree)
  --publish                 Push master and the new tag. The tag triggers
                            .github/workflows/release.yml, which publishes to
                            npm. Without this flag the commit and tag stay
                            local.
  --dry-run                 Validate and print the plan, then exit
  -h, --help                Show this help

Preconditions: on master, no uncommitted changes to tracked files.
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

bump=""
version_arg=""
current=0
publish=0
dry_run=0

while [ $# -gt 0 ]; do
    case "$1" in
        --bump)
            [ $# -ge 2 ] || die "--bump needs a value"
            bump="$2"
            shift 2
            ;;
        --version)
            [ $# -ge 2 ] || die "--version needs a value"
            version_arg="$2"
            shift 2
            ;;
        --current)
            current=1
            shift
            ;;
        --publish)
            publish=1
            shift
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

modes=0
if [ -n "$bump" ]; then
    modes=$((modes + 1))
fi
if [ -n "$version_arg" ]; then
    modes=$((modes + 1))
fi
if [ "$current" -eq 1 ]; then
    modes=$((modes + 1))
fi
[ "$modes" -eq 1 ] ||
    die "specify exactly one of --bump, --version or --current"

root=$(git rev-parse --show-toplevel 2>/dev/null) ||
    die "not a git repository"
cd "$root"

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = "master" ] ||
    die "releases are cut from master, not '$branch'"

git diff --quiet ||
    die "uncommitted changes to tracked files; commit or stash them first"
git diff --cached --quiet ||
    die "staged but uncommitted changes; commit them first"

current_version=$(node -p "require('./package.json').version" 2>/dev/null) ||
    die "could not read version from package.json"
semver_re='^[0-9]+\.[0-9]+\.[0-9]+$'
echo "$current_version" | grep -Eq "$semver_re" ||
    die "package.json version '$current_version' is not x.y.z"

if [ -n "$version_arg" ]; then
    echo "$version_arg" | grep -Eq "$semver_re" ||
        die "--version must be x.y.z (numeric only)"
    new_version="$version_arg"
elif [ -n "$bump" ]; then
    IFS=. read -r major minor patch <<< "$current_version"
    case "$bump" in
        major) new_version="$((major + 1)).0.0" ;;
        minor) new_version="$major.$((minor + 1)).0" ;;
        patch) new_version="$major.$minor.$((patch + 1))" ;;
        *) die "--bump must be patch, minor or major" ;;
    esac
else
    new_version="$current_version"
fi

if [ "$current" -eq 0 ] && [ "$current_version" = "$new_version" ]; then
    die "version unchanged ($current_version); use --current to tag it as-is"
fi

tag="v$new_version"

# Checked before anything is written: `git tag` would otherwise abort after
# the bump commit landed, leaving master with an untagged version commit.
if git rev-parse --verify --quiet "refs/tags/$tag" >/dev/null; then
    die "tag $tag already exists locally"
fi
if [ -n "$(git ls-remote --tags origin "refs/tags/$tag" 2>/dev/null || true)" ]; then
    die "tag $tag already exists on origin"
fi

base_commit=$(git rev-parse HEAD)

if [ "$publish" -eq 1 ]; then
    remote_master=$(git rev-parse --verify --quiet refs/remotes/origin/master || true)
    [ -n "$remote_master" ] ||
        die "no origin/master; fetch the remote first"
    [ "$base_commit" = "$remote_master" ] ||
        die "HEAD is not origin/master; fetch and fast-forward first (git pull --ff-only)"
    if npm view "xpi-ts@$new_version" version >/dev/null 2>&1; then
        die "npm already has xpi-ts@$new_version"
    fi
fi

if [ "$dry_run" -eq 1 ]; then
    echo "Release plan"
    echo "  branch:  master"
    if [ "$new_version" = "$current_version" ]; then
        echo "  version: $current_version (current; no bump commit)"
    else
        echo "  version: $current_version -> $new_version"
        echo "  commit:  Bump version to $new_version"
    fi
    echo "  tag:     $tag (annotated)"
    echo "  preflight: format:check, lint, test, build, package smoke"
    if [ "$publish" -eq 1 ]; then
        echo "  publish: git push origin master $tag (triggers the OIDC workflow)"
    else
        echo "  publish: skipped (no --publish); commit and tag stay local"
    fi
    exit 0
fi

echo "Running preflight..."
npm run format:check
npm run lint
npm test
npm run build
./scripts/smoke-package.sh
echo "Preflight passed."

if [ "$new_version" != "$current_version" ]; then
    echo "Bumping version: $current_version -> $new_version"
    npm version --no-git-tag-version --ignore-scripts "$new_version" >/dev/null

    package_version=$(node -p "require('./package.json').version")
    lock_version=$(node -p "require('./package-lock.json').version")
    lock_package_version=$(
        node -p "require('./package-lock.json').packages[''].version"
    )
    [ "$package_version" = "$new_version" ] ||
        die "package.json declares '$package_version', expected '$new_version'"
    [ "$lock_version" = "$new_version" ] ||
        die "package-lock.json declares '$lock_version', expected '$new_version'"
    [ "$lock_package_version" = "$new_version" ] ||
        die "package-lock.json packages[''] declares '$lock_package_version'"

    changed=$(git diff --name-only | sort | tr '\n' ' ')
    [ "$changed" = "package-lock.json package.json " ] ||
        die "unexpected files changed by the bump: $changed"

    git add package.json package-lock.json
    git commit -m "Bump version to $new_version"
else
    echo "Releasing the current version $current_version without a bump commit"
fi

git tag -a "$tag" -m "$new_version"

if [ "$publish" -eq 1 ]; then
    echo "Pushing master and $tag..."
    git push origin master "$tag"
    echo
    echo "Pushed. GitHub Actions publishes xpi-ts@$new_version. Follow it with:"
    echo "  gh run list --workflow=release.yml --limit 1"
else
    echo
    echo "Cut locally: $tag points at master and is not pushed."
    echo "Publish it (this triggers the OIDC workflow) with:"
    echo "  git push origin master $tag"
fi
