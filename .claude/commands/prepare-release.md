Prepare the project for release. Follow each step in order. Stop and report if any step fails.

## Step 1: Sync license headers

The `LICENSE` file is the single source of truth for the copyright notice.

1. **Update the LICENSE year.** Read `LICENSE` and ensure the copyright year range ends with the current year (e.g. `2015-2026`). If it doesn't, update it.
2. **Build the header template.** Convert the full text of `LICENSE` (after the year fix) into a Go block-comment header:
   ```
   /*
    * <each line of LICENSE prefixed with " * ">
    */
   ```
3. **Apply to every handwritten `.go` file.** For each `.go` file in the repo (excluding `vendor/` and auto-generated files like `phe.pb.go`):
   - If the file already has a license header block comment at the top, replace it with the freshly built template.
   - If the file has no license header, insert the template at the very top of the file.
4. **Commit.** Stage all changed files and commit with message: `chore: sync license headers with LICENSE file`.

## Step 2: Run all tests

Run the full test suite and ensure every test passes.

```
go test ./... -v
```

If any test fails, stop and report the failures. Do not proceed.

## Step 3: Check test coverage

Run coverage and report the numbers. Flag any hand-written (non-generated) source file with coverage below 80%.

```
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

Exclude auto-generated files (e.g. `phe.pb.go`) from the analysis.

## Step 4: Update CHANGELOG.md

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

## Step 5: Review README.md

Read README.md and check that:
- Installation instructions reference the correct module path.
- API examples still match the current public API (exported functions/types in non-generated `.go` files).
- No broken links or obviously stale information.

Report any issues found. If changes are needed, propose them and ask for confirmation before editing.

## Step 6: Summary

Print a release readiness summary:
- Branch: master
- Tests: PASS / FAIL
- Coverage: X%
- CHANGELOG.md: updated / already up to date
- README.md: OK / issues found
- Next step: suggest `git tag v<version> && git push origin master --tags`
