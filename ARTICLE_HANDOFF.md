# Article handoff: Port Map Check

## Project facts

- Repository: https://github.com/configcrate/port-map-check
- Release: https://github.com/configcrate/port-map-check/releases/tag/v0.1.0
- Website backlink: https://configcrate.com/
- License: MIT
- Language: Go 1.24+
- Runtime dependency: yaml.v3
- Status: v0.1.0 released

## One-sentence description

Port Map Check scans Docker Compose, Kubernetes, Dockerfiles, devcontainers,
healthchecks, probes, Ingress backends, and service URLs to find port conflicts
and broken service wiring before a stack starts.

## User pain

One repository can describe the same application port as a host mapping, a
container target, a Dockerfile `EXPOSE`, a Kubernetes container port, a Service
port, a `targetPort`, a NodePort, an Ingress backend, and a healthcheck URL.
Each file can be syntactically valid while the combined topology is broken.

The common examples are concrete and easy to demonstrate:

- `8080:3000`, followed by a container healthcheck for `localhost:8080`;
- `postgres://db:5433` between Compose services when `5433:5432` is the host
  mapping and the database listens on `5432`;
- two services publishing the same host port;
- a named Kubernetes `targetPort` that no selected workload declares;
- an Ingress backend using a Service port that does not exist;
- two manifests reserving the same NodePort;
- Compose targeting port 3000 while the selected Dockerfile documents 4000.

## Primary references

- Docker Compose networking and the host-port/container-port distinction:
  https://docs.docker.com/compose/how-tos/networking/
- Docker published ports:
  https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/
- Kubernetes Service and `targetPort` behavior:
  https://kubernetes.io/docs/concepts/services-networking/service/
- Kubernetes container probes:
  https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/
- Dev Container `forwardPorts` reference:
  https://containers.dev/implementors/json_reference/

## Differentiation

- Not a live TCP port scanner.
- Not a generic YAML style linter.
- Not a Docker daemon or Kubernetes cluster inspector.
- Correlates declarations across files and platforms.
- Understands the difference between host, container, Service, target, NodePort,
  Ingress, probe, and forwarded ports.
- Extracts explicit service URLs without retaining credentials or query strings.
- Uses severity carefully where Kubernetes declarations are documentary rather
  than mandatory.
- Requires no credentials, daemon, cluster, or network access.
- Produces text, JSON, self-contained HTML, and a GitHub job summary.

## Strong article angles

1. "Your YAML is valid, but your ports are wired wrong"
2. "Why `db:5433` fails inside Docker Compose when `5433:5432` looks correct"
3. "Map every host, container, Service, NodePort, and Ingress port in one command"
4. "Seven port mistakes CI can find before Docker or Kubernetes starts"
5. "The difference between Compose host ports and container ports, visualized"

## Suggested article structure

1. Start with a valid-looking `8080:3000` mapping and the wrong internal URL.
2. Explain host-side versus service-to-service ports.
3. Add Kubernetes Service and Ingress examples to show the same problem at a
   larger scale.
4. Run `port-map-check scan .` against `examples/broken-stack`.
5. Walk through the most actionable findings and suggested fixes.
6. Compare with `examples/healthy-stack`.
7. Generate the HTML report and add the GitHub Action.
8. State the static-analysis limitations and link the repository, release, and
   ConfigCrate.

## Verified commands

```bash
port-map-check scan .
port-map-check scan . --fail-on warning
port-map-check scan . --format json --output port-map.json --fail-on never
port-map-check scan . --format html --output port-map-report.html --fail-on never
port-map-check scan examples/broken-stack --fail-on never
port-map-check scan examples/healthy-stack --fail-on warning
```

## Important accuracy language

Say that a finding is a static configuration conflict or mismatch. Do not claim
that Port Map Check observes runtime reachability. Numeric Kubernetes
`containerPort` is optional, so numeric Service/probe mismatches are warnings.
Named ports must resolve and can be treated as errors. Dockerfile `EXPOSE` is
documentation, so its mismatch is also a warning.

Compose files are analyzed independently because development and production
stacks often reuse host ports intentionally. Helm templates are skipped until
rendered.

## Screens and examples

- README preview: `docs/report-preview.svg`
- Broken example: `examples/broken-stack`
- Corrected example: `examples/healthy-stack`
- HTML report: summary cards, findings, normalized port inventory, detected URL
  references, and ConfigCrate backlink.
