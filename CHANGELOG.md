# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- IPv4 (bitflip) support with dedicated client/server
- IPv6 (bitflip6) support with dedicated client/server
- **kuiniu**: GPU NIC interconnect probing tool for AI training clusters
  - GPU pair model with parallel `local_gpu_addrs` / `remote_gpu_addrs` arrays
  - JSON config file with CLI flag override support
  - `role=both` for single-process client + server with `localGPUSet` self-echo guard
  - Concurrent client/server execution under shared context/processor/logger
  - 4-Salt bit-flip detection on RoCEv2/UDP paths
  - Logs to both terminal and file, with key milestone logs at startup
  - Continues running when client/server `Run()` returns error (no process exit)
- `util.RotateWriter`: shared daily-rotated log writer with stable symlink and prefix-isolated pruning, used by both `baize` and `kuiniu`
- Per-tool documentation page `docs/kuiniu.html`; `docs/index.html` updated with kuiniu section, tool index entry, and comparison table column

### Fixed
- kuiniu client peer matching now uses the correct IP field
