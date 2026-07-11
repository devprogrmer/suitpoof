# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-07-11

### Added
- Added hardened `suit-manager.sh` (v3.0.0) with safer Bash defaults:
  - `set -Eeuo pipefail`
  - centralized error trap (`on_err`)
  - dependency checks (`need_cmd`)
  - directory bootstrap (`ensure_dirs`)
- Added full command set for lifecycle management:
  - `setup`, `download`, `update`, `configure`, `gen-quic-cert`
  - `start`, `stop`, `restart`, `enable`, `disable`, `remove`
  - `status`, `logs`, `follow`, `uninstall`
- Added dynamic GitHub release binary fetch support.
- Added hardened systemd unit profile:
  - capability bounding and ambient capabilities
  - `NoNewPrivileges=true`
  - `PrivateTmp=true`
  - `ProtectSystem=full`
  - `ProtectHome=true`
- Added interactive helpers:
  - `ask`, `ask_bool`
  - input validators (`validate_ip`, `validate_port`)
  - random generators (`random_hex`)
- Added repository scaffolding:
  - `LICENSE` (MIT)
  - `.gitignore`
  - `CHANGELOG.md`
- Added example configs:
  - `examples/client.toml`
  - `examples/server.toml`

### Changed
- Improved README with stronger focus on SuitTunnel architecture and DPI-evasion model.
- Clarified separation of:
  - `real_ip` / `peer_real_ip`
  - `spoofed_ip` / `peer_spoofed_ip` / `spoofed_ip_pool`
- Expanded docs for deployment patterns, troubleshooting, and operational safety.

### Notes
- Example TOML files are templates and must be edited per environment.
- `pre_shared_key` must match on both sides.
- `real_ip` / `peer_real_ip` must be routable between peers.
