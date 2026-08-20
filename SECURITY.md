# Security policy

## Supported versions

Security fixes are applied to the latest revision of `main`. The supported
runtime is Ubuntu 22.04 LTS or newer with its system Python 3 interpreter.

## Reporting a vulnerability

Do not include exploit details in a public issue. Use GitHub private
vulnerability reporting when it is enabled, or contact the repository owners
through the organization's private security channel. Include the affected
revision, runner image, a minimal reproduction, and the expected impact.

## Security boundaries

This action runs APT and `dpkg` with `sudo`, as required on GitHub-hosted Ubuntu
runners. It therefore treats its own source, configured APT repositories, and
the runner image as trusted. Package input is untrusted data and is validated
before use. Restored cache entries are never executed or extracted into the
root filesystem; only single-link regular `.deb` files are accepted and APT
validates them against freshly refreshed, signed repository metadata before
installation.

See [docs/security-audit.md](docs/security-audit.md) for the detailed review.
