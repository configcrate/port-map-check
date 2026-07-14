# Changelog

All notable changes to Port Map Check are documented here.

## [Unreleased]

## [0.1.0] - 2026-07-14

### Added

- Docker Compose service, port, environment URL, healthcheck, profile, and build-context discovery.
- Kubernetes workload, container port, probe, Service, selector, NodePort, Ingress, and environment URL discovery.
- Dockerfile `EXPOSE` and devcontainer `forwardPorts` inventory.
- Cross-resource rules for host-port conflicts, container-localhost mistakes, service-to-service port confusion, Kubernetes port/selector/backend mismatches, and Dockerfile/Compose drift.
- Text, JSON, and self-contained HTML reports.
- Configurable CI exit thresholds.
- Docker-based GitHub Action.
- Linux, macOS, and Windows release builds.

[Unreleased]: https://github.com/configcrate/port-map-check/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/configcrate/port-map-check/releases/tag/v0.1.0
