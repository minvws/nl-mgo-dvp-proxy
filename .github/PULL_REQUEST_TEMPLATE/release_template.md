## Release vX.Y.Z

Provide a brief description of the release.

## Checklist

### Pre-release actions

- [ ] A new [GitHub release](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository#creating-a-release) has been created, including verified release notes.
- [ ] Verify the ticket status of all included pull requests.
- [ ] All checks are passing in CI.
- [ ] Feature flags have been reviewed.
- [ ] `HOSTING_CHANGELOG.md` has been updated.
- [ ] Manual QA has been completed on a local machine (for RC releases only).
- [ ] Release tag is prepared (`vX.Y.Z` / `vX.Y.Z-rcX`).

### Post-release actions

- [ ] Notify the team in [#mgo-release](https://minvws-rdo.slack.com/archives/C07LX97C2AD).
- [ ] Perform a sanity check.
- [ ] Monitor metrics in Grafana.
- [ ] Trigger a new test run of the [regression tests](https://github.com/minvws/nl-mgo-coordination-private/actions/workflows/regression-on-pr.yml) and notify the QA team if any tests fail.
