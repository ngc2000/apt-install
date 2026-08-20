# Security audit and design review

Audit date: 2026-08-20

Scope: the inherited `action`, `action.yml`, test workflow, dependency update
configuration, and the APT/cache trust boundary. The intended workload is
`libidn-dev` and `libpcap-dev` on GitHub-hosted Ubuntu 22.04 and newer.

## Executive decision

Do not cache installed filesystem trees. Cache only downloaded `.deb` archives
and run a normal APT installation on every invocation. This is slower than
restoring files into `/`, but keeps APT authentication, dependency resolution,
`dpkg` state, conffile handling, triggers, and maintainer scripts in the trusted
installation path.

APT documents `/var/cache/apt/archives` as its retrieved-package storage and
automatically verifies downloaded package checksums through signed repository
metadata. Debian Policy also makes clear that installation is a stateful
sequence involving pre-installation scripts, unpacking, status updates, and
post-installation configuration; copying a package's file list is not an
equivalent installation.

## Findings in the inherited implementation

| Severity | Finding | Resolution |
| --- | --- | --- |
| Critical | `inputs.packages` and `inputs.version` were interpolated directly into a generated Bash script. A quote-breaking value could execute arbitrary commands. | Inputs are passed through step environment variables, validated, normalized, and supplied to APT in a subprocess argument vector. |
| High | A cache-controlled tar archive was extracted with `sudo` directly into `/` without validating members. Cache compromise therefore became privileged arbitrary file overwrite. | Root-filesystem archives were removed. Restored cache directories may contain only single-link regular `.deb` files. |
| High | Cache hits copied files without updating the `dpkg` database or running package maintainer scripts and triggers. | Every run uses `apt-get install`; cache hits only avoid some downloads. |
| High | The cache key omitted Ubuntu version, CPU/dpkg architecture, repositories, preferences, resolved update period, and package-manager schema. Security updates could remain bypassed indefinitely. | The key includes release, architectures, source/preference digest, normalized inputs, schema, manual salt, and a UTC week. APT indexes are refreshed on every run. |
| High | `actions/cache@v6` and the test action's `@main` reference were mutable supply-chain dependencies. | Third-party actions are pinned to full reviewed commit SHAs; CI tests the local checkout. |
| Medium | Installed packages were inferred by parsing localized human-readable APT output for `Unpacking`. | No human-readable output is parsed. APT's exit status and `dpkg --audit` determine success. |
| Medium | Unquoted variables, `xargs`, and newline-sensitive environment-file writes made whitespace and control-data handling brittle. | Python path objects and subprocess argument vectors preserve boundaries, and only generated hashes/paths are written to the environment file. |
| Low | MD5 was used for cache identity. Collision resistance was not the primary security boundary, but it was an avoidable weakness. | All internal digests use SHA-256. |
| Low | The action did not define a supported platform or test current Ubuntu releases. | Unsupported systems fail early; CI covers Ubuntu 22.04, 24.04, and 26.04. |

## Threat model

Trusted inputs:

- the reviewed revision of this repository;
- the GitHub-hosted runner image and its passwordless `sudo` policy;
- APT repositories explicitly configured by the calling workflow;
- the pinned `actions/cache` implementation.

Untrusted or potentially stale inputs:

- action input strings;
- restored cache contents;
- network-delivered package archives;
- old package archives restored by a prefix key.

Controls:

- strict package grammar prevents command and APT-option injection;
- the implementation uses Python 3.10-compatible standard-library APIs and
  passes every privileged command as an argument vector without a shell;
- cache paths are confined beneath `RUNNER_TEMP` and have a fixed hash layout;
- symbolic links, hard links, and every cache entry other than a regular `.deb`
  are rejected;
- `apt-get update --error-on=any` refreshes and authenticates repository state;
- APT selects candidate versions and validates archive checksums;
- `--no-remove` prevents an unattended package request from removing packages;
- archives are saved immediately after a successful install, before caller steps
  can modify the cache directory;
- GitHub's branch and event cache scopes remain an additional defense, not the
  primary integrity control.

## Alternatives reviewed

### `daaku/gh-action-apt-install`

The original is tiny and a cache hit is fast. Its defining optimization is also
the unacceptable boundary for this use case: it archives `dpkg -L` results and
extracts them into `/`, while explicitly noting that post-installation scripts
do not run. It also contains the injection and cache-key issues listed above.

### `tecolicom/actions-use-apt-tools`

This action offers repository support plus package-list and timestamp discovery
methods. Both methods still restore an installed filesystem archive. The
timestamp method can include `/etc` and `/var/lib`, increasing the amount of
privileged mutable system state in the cache. Its feature set is useful where
speed is valued over package-manager fidelity, but it does not remove the root
archive trust problem.

### `awalsh128/cache-apt-pkgs-action`

This is more mature and records package/version manifests. It documents the
non-file dependency problem and optionally attempts maintainer scripts on
restore. However, v1 remains based on restoring per-package tar files into `/`,
and its current installation path bootstraps `apt-fast` by executing a script
downloaded from a mutable upstream branch. Its README states that v1 is in
maintenance mode while a v2 beta is planned. Those properties do not fit the
desired supply-chain boundary.

### Plain `apt-get`

This is the smallest, safest baseline and may be the fastest practical choice
for `libidn-dev` and `libpcap-dev`, which are relatively small. The selected
design is intentionally close to this baseline: it adds only an authenticated
download cache and never skips APT installation.

### Prebuilt image

A reviewed container or custom runner image can remove nearly all repeated APT
work and improve reproducibility. It adds image build, patching, provenance,
and rollout duties. Revisit this option if native dependencies grow or package
installation becomes a meaningful share of job time.

## Residual risks and operating guidance

- A trusted APT repository can still distribute malicious packages. APT
  authentication proves repository provenance and integrity, not package
  harmlessness.
- The default package specification installs the current candidate. Use an
  exact `=version` and snapshot repository when byte-for-byte reproducibility is
  required.
- A caller can configure a malicious repository before invoking the action.
  Repository changes therefore require the same review as workflow code.
- Cached `.deb` files can consume repository cache quota. Weekly keys are
  intentionally bounded by normal GitHub cache eviction; monitor usage if the
  package set grows.
- Self-hosted runners have a larger persistence and cross-job threat surface.
  This review targets ephemeral GitHub-hosted runners.

## Primary references

- [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub dependency caching and cache security](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [Ubuntu 22.04 `apt-get` manual](https://manpages.ubuntu.com/manpages/jammy/man8/apt-get.8.html)
- [Ubuntu 22.04 `apt-secure` manual](https://manpages.ubuntu.com/manpages/jammy/man8/apt-secure.8.html)
- [Ubuntu 24.04 `apt-get` manual](https://manpages.ubuntu.com/manpages/noble/man8/apt-get.8.html)
- [Ubuntu 24.04 `apt-secure` manual](https://manpages.ubuntu.com/manpages/noble/man8/apt-secure.8.html)
- [Debian Policy: maintainer scripts and installation procedure](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html)
- [GitHub-hosted runner images](https://github.com/actions/runner-images)
- [Original action](https://github.com/daaku/gh-action-apt-install)
- [tecolicom/actions-use-apt-tools](https://github.com/tecolicom/actions-use-apt-tools)
- [awalsh128/cache-apt-pkgs-action](https://github.com/awalsh128/cache-apt-pkgs-action)
