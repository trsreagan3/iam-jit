#!/bin/bash
# #600: Fail if any /Users/<name> or /home/<name> appears in non-test
# source. Per [[push-policy-public-repo]]: personal filesystem paths
# are information disclosure in a public repo.
#
# Invoked by .pre-commit-config.yaml on staged files (pre-commit passes
# the file list as positional args). Also runnable standalone over a
# tree:
#
#   ./scripts/check_no_personal_paths.sh src/iam_jit/**/*.py
#
# Excludes test files + fixtures + AUDIT-* security docs (which
# legitimately record the personal paths an attacker would see).
set -euo pipefail

if [ "$#" -eq 0 ]; then
  # No files passed — nothing to check (pre-commit semantics).
  exit 0
fi

# Filter out legitimate exclusions BEFORE grepping so the error output
# only mentions real violations. We exclude based on BASENAME (not
# path-anywhere) so a pytest tmpdir like
# /var/.../test_pre_commit_hook_catches_v0/violator.py doesn't get
# spuriously excluded just because an ancestor dir starts with `test_`.
files_to_check=()
for f in "$@"; do
  bn=$(basename "$f")
  case "$bn" in
    test_*) continue ;;  # Python pytest convention
    *_test.go) continue ;;  # Go test convention
    *_test.py) continue ;;  # alt Python test convention
  esac
  # Path-component exclusions for fixtures + audit reports. We anchor
  # with explicit `/` boundaries so `myfixturesfile.py` doesn't get
  # excluded but `src/iam_jit/fixtures/foo.py` does.
  case "/$f" in
    */tests/*) continue ;;
    */fixtures/*) continue ;;
    */docs/security/AUDIT-*) continue ;;
  esac
  if [ -f "$f" ]; then
    files_to_check+=("$f")
  fi
done

if [ "${#files_to_check[@]}" -eq 0 ]; then
  exit 0
fi

# Pattern matches /Users/<lowercase-name> or /home/<lowercase-name>.
# Tilde + relative paths are fine (~/.kube/config, ./foo, src/foo).
violations=$(grep -nE "/Users/[a-z]+|/home/[a-z]+" "${files_to_check[@]}" || true)

if [ -n "$violations" ]; then
  echo "ERROR: personal filesystem paths found in non-test source:" >&2
  echo "$violations" >&2
  echo "" >&2
  echo "Per [[push-policy-public-repo]] these MUST NOT be committed to a" >&2
  echo "public repo (information disclosure). Use repo-relative refs or" >&2
  echo "canonical placeholders (~/.kube/config, ./foo, <repo>/path):" >&2
  echo "" >&2
  echo "  bad:  /Users/reagan/repos/foo/bar.go" >&2
  echo "  good: foo: bar.go   OR   ~/.iam-jit/dynamic-denies.yaml" >&2
  exit 1
fi

exit 0
