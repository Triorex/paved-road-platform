# JFrog design: the enterprise "front door" for open source (design and config only)

In the demo, `scripts/curation_check.py` enforces the curation policy in CI. In the enterprise
target, JFrog enforces the same policy **at download time** for every developer laptop and every
build, so a malicious package never reaches a workstation in the first place.

## Repository layout (per ecosystem: pypi, npm, maven, docker, go)

```
<eco>-virtual   <- the ONLY URL developers and builds use (pip index-url, .npmrc, docker mirror)
 ├── <eco>-local      internal packages, published by CI only
 └── <eco>-remote     proxy + cache of the public registry, with JFrog Curation applied
release-docker-dev -> release-docker-staging -> release-docker-prod
                    promotion moves the SAME build (by build-info and digest); nothing is rebuilt
```

- **Dependency confusion:** remote repos exclude the internal namespaces (`@triorex/*`, `triorex-*`),
  so a public package can never shadow an internal name.
- **No direct internet:** runners and laptops reach public registries only through `*-remote`.
- **Authentication:** GitHub Actions uses OIDC (`jfrog/setup-jfrog-cli` with `oidc-provider-name`),
  so no Artifactory tokens are stored in GitHub.

## Policies (files in this folder)

| File | What it enforces |
|---|---|
| `repositories.yaml` | Local, remote and virtual repos, include/exclude patterns, Xray indexing |
| `curation-policies.json` | Block malicious packages, immature releases (< 7 days), CVSS ≥ 9 with a fix available, banned licenses |
| `xray-policies.json` | Security policy (high+ with a fix fails the build) and license policy |
| `xray-watch.json` | Applies both policies to the remote and release repos and to every build |

## How the paved road calls it

`secure-build.yml` has the JFrog steps already wired in, behind the org variable
`JFROG_ENABLED` (off in the demo): set up the JFrog CLI through OIDC, resolve dependencies through
the virtual repos, and run `jf audit` against the `paved-road-prod` watch. Turning the variable on
for a ring of repos is the rollout.
