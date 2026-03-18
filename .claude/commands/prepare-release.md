Prepare the project for release. Follow each step in order. Stop and report if any step fails.

## Step 1: Run all tests

Run the full test suite and ensure every test passes.

```
go test ./... -v
```

If any test fails, stop and report the failures. Do not proceed.

## Step 2: Check test coverage

Run coverage and report the numbers. Flag any hand-written (non-generated) source file with coverage below 80%.

```
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

Exclude auto-generated files (e.g. `phe.pb.go`) from the analysis.

## Step 3: Update CHANGELOG.md

1. Read the current CHANGELOG.md (create it if it doesn't exist).
2. Read the git log since the last release tag (or all history if no tags exist):
   ```
   git log --oneline $(git describe --tags --abbrev=0 2>/dev/null || git rev-list --max-parents=0 HEAD)..HEAD
   ```
3. Summarize the changes into a new release section at the top of the changelog using [Keep a Changelog](https://keepachangelog.com/) format:
   - Group entries under: Added, Changed, Fixed, Removed (only include sections that apply).
   - Use the current date for the release header.
   - Ask the user for the version number if not provided as an argument.
4. Commit the changelog update with message: `chore: update CHANGELOG.md for <version>`.

## Step 4: Review README.md

Read README.md and check that:
- Installation instructions reference the correct module path.
- API examples still match the current public API (exported functions/types in non-generated `.go` files).
- No broken links or obviously stale information.

Report any issues found. If changes are needed, propose them and ask for confirmation before editing.

## Step 5: Summary

Print a release readiness summary:
- Branch: master
- Tests: PASS / FAIL
- Coverage: X%
- CHANGELOG.md: updated / already up to date
- README.md: OK / issues found
- Next step: suggest `git tag v<version> && git push origin master --tags`
