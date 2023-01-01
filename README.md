# pdm-sbom

Generate Software Bill of Materials from PDM based projects

**Note**: This is still a pre-development state.

## Open topics

- [ ] CLI Options
- [ ] Create a wheel
- [ ] Refactor implementation (Too large parser module, too large sbom namespace)
- [ ] Refactor implementation for improved testing
- [ ] Create tests
- [ ] Add CI/CT/CD Pipeline
- [ ] Improve documentation
- [ ] Divide components into application, framework, etc
- [ ] Add validation, e.g. missing license or author
- [ ] Add parser for TROVE classifiers
- [ ] Add more data to `Project` entity to fill in gaps
- [ ] Unify implementation for meta data extraction
- [ ] Wait for SDPX-Tools 0.7.0 to be published on pypi

## Purpose

When developing software, gathering the tree of used software for the development including the runtime-dependencies is essential in some cases.
The so called software bill of materials is an essential piece of software development.

This [pdm](https://pdm.fming.dev) plugin analyzes the output of `pdm list` and divides the output into a hierarchical dependency tree including development and optional dependencies.
This tree is enriched with the module meta data consisting of authors and licenses.

In the end, three different SBOMs can be created:

- a regular JSON file.
- an [spdx](https://spdx.org) file in Version 1.0 to 2.3, either as
  - JSON
  - YAML
  - XML
  - RDF (XML)
  - SPDX Tag-Value
- a [cyclonede](https://cyclonedx.org) file in version 1.0 to 1.4, either as
  - XML
  - JSON

The resulting file will be stored in the `dists` folder next to the resulting wheel.
