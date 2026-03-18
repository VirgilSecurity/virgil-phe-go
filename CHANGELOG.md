# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-03-18

### Changed

- Migrated to Go modules (Go 1.26); removed legacy dep (Gopkg.lock/Gopkg.toml)
- Replaced `pkg/errors` with standard library error wrapping (`fmt.Errorf`)
- Switched CI from Travis CI to GitHub Actions
- Updated README with revised installation instructions and API examples

### Added

- Extended test coverage for client, server, models, utils, and SWU packages
- Synced license headers across all handwritten `.go` files with LICENSE file
