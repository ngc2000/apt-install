# apt-install

Install APT packages on GitHub-hosted Ubuntu runners while caching downloaded
`.deb` archives. This fork is maintained for our internal workflows and targets
Ubuntu 22.04 and newer.

Unlike the original action, this action never restores package files directly
into `/`. Every invocation refreshes signed APT indexes and runs a normal
`apt-get install`, so `dpkg` records, dependency handling, conffiles, triggers,
and package maintainer scripts remain authoritative.

## Usage

Pin the action to a reviewed full commit SHA in consuming workflows:

```yaml
- name: Install native dependencies
  uses: ngc2000/apt-install@<full-commit-sha>
  with:
    packages: |
      libidn-dev
      libpcap-dev
```

`packages` is whitespace-delimited. Supported specifications are `package`,
`package:architecture`, and either form with an exact `=version`. Shell syntax,
APT flags, regex/glob matching, release selectors, and removal requests are
rejected.

The optional `version` input is a manual cache-key salt:

```yaml
  with:
    packages: libidn-dev libpcap-dev
    version: "2"
```

## Cache behavior

The cache contains only regular `.deb` files downloaded and verified by APT.
Keys include the Ubuntu release, native and foreign architectures, configured
APT sources and preferences, normalized package list, cache schema, and the
manual `version` input. A new primary key is created each UTC week, with the
previous cache used as a download seed.

An exact cache hit does **not** skip installation. APT still selects the current
candidate versions from freshly downloaded, signed repository metadata and
validates cached archives before installing them.

This design optimizes network downloads, not the package-manager work itself.
For very small packages, plain `apt-get` may be just as fast. For large and
stable toolchains used across many jobs, a reviewed container image or runner
image may provide better speed and reproducibility.

See [the security audit](docs/security-audit.md) for the threat model, findings,
and comparison with other APT caching actions.

## Support

- Ubuntu 22.04 LTS and newer GitHub-hosted runners
- The system `/usr/bin/python3` (Python 3.10 or newer; no third-party modules)
- APT repositories configured before this action runs
- `actions/cache` v6, pinned to a reviewed commit

Other Linux distributions and Ubuntu releases older than 22.04 fail early.
Third-party repositories remain the caller's responsibility and should use a
dedicated keyring plus `Signed-By`.

## License and attribution

MIT licensed. This project is derived from
[daaku/gh-action-apt-install](https://github.com/daaku/gh-action-apt-install),
originally written by Naitik Shah. See [NOTICE](NOTICE) and [license](license).
