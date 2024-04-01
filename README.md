# pdm-sbom

Generate Software Bill of Materials from PDM based projects. This project is now in public beta.

## Open topics

- [ ] Create tests
- [ ] Add CI/CT/CD Pipeline
- [ ] Improve documentation
- [ ] Divide components into application, framework, etc
- [ ] Add validation, e.g. missing license or author
- [ ] Add parser for TROVE classifiers
- [ ] Parse Metadata / dist-info files
- [ ] Post build hook

## Purpose

When developing software, gathering the tree of used software for the development including the runtime-dependencies is essential in some cases.
The so called software bill of materials is an essential piece of software development.

This [pdm](https://pdm.fming.dev) plugin analyzes the lock file from `pdm.toml` and divides the output into a hierarchical dependency tree including development and optional dependencies.
This tree is enriched with the module meta data consisting of authors and licenses.

In the end, three different SBOMs can be created:

- a regular JSON file.
- an [spdx](https://spdx.org) file in Version 1.0 to 2.3, either as
  - JSON
  - YAML
  - XML
  - RDF (XML)
  - SPDX Tag-Value
- an [spdx3](https://spdx.org) file in version 3.0, as
  - jsonld
- a [cyclonede](https://cyclonedx.org) file in version 1.0 to 1.5, either as
  - XML
  - JSON
- a [jfrog buildinfo](https://buildinfo.org) file in version 1 as
  - json

## Usage

```shell
$ pdm sbom -h
Usage: pdm sbom [-h] [-v | -q] [-g] [-p PROJECT_PATH] [--format {json,cyclonedx,spdx,spdx3,buildinfo}] [--output OUTPUT_FILE] [--dest DESTINATION_FOLDER] [--target-dir TARGET_DIR] [--cyclonedx-format {json,xml}]
 [--cyclonedx-version {1.2,1.0,1.3,1.5,1.4,1.1}] [--spdx-format {yml,json,xml,yaml,tag,rdf-xml,rdf,spdx}] [--spdx-version {1.2,2.0,1.0,2.1,2.2,2.3,1.1}] [--spdx3-format {jsonld}] [--spdx3-version {3.0}]

Generate a Software Bill of Materials according to your project

Options:
  -h, --help            Show this help message and exit.
  -v, --verbose         Use `-v` for detailed output and `-vv` for more detailed
  -q, --quiet           Suppress output
  -g, --global          Use the global project, supply the project root with `-p` option
  -p PROJECT_PATH, --project PROJECT_PATH
                        Specify another path as the project root, which changes the base of pyproject.toml and __pypackages__ [env var: PDM_PROJECT]
  --format {json,cyclonedx,spdx,spdx3,buildinfo}, -f {json,cyclonedx,spdx,spdx3,buildinfo}
                        Select the sbom file format. Defaults to json. Available formats are: json (Pure JSON Serialization - unstable), cyclonedx (CycloneDX file format - supported versions: 1.2, 1.0, 1.3, 1.5, 1.4, 1.1 - supported
                        formats: json, xml), spdx (SPDX file format - supported versions: 1.2, 2.0, 1.0, 2.1, 2.2, 2.3, 1.1 - supported formats: yml, json, xml, yaml, tag, rdf-xml, rdf, spdx), spdx3 (Experimental SPDX 3 support),
                        buildinfo (JFrog Build Info file format. Can only be written as JSON file.)
  --output OUTPUT_FILE, -o OUTPUT_FILE
                        Sets the target file to write the generated sbom to. Defaults to <project-name>.<extension>.Use - for stdout.
  --dest DESTINATION_FOLDER, -d DESTINATION_FOLDER
                        Gets the directory, where the generated binaries have been stored. Defaults to 'dist'.
  --target-dir TARGET_DIR, -t TARGET_DIR
                        Gets the directory, where the generated sbom files shall be stored. Defaults to <project-dir>.

Cyclonedx Options:
  Options for exporting cyclonedx sbom documents.

  --cyclonedx-format {json,xml}, -cf {json,xml}
                        Select the file output format to set for exported cyclonedx file. Defaults to json.
  --cyclonedx-version {1.2,1.0,1.3,1.5,1.4,1.1}, -cv {1.2,1.0,1.3,1.5,1.4,1.1}
                        Select the file version to set for exported cyclonedx file. Defaults to version 1.5.

Spdx Options:
  Options for exporting spdx sbom documents.

  --spdx-format {yml,json,xml,yaml,tag,rdf-xml,rdf,spdx}, -sf {yml,json,xml,yaml,tag,rdf-xml,rdf,spdx}
                        Select the file output format to set for exported spdx file. Defaults to json.
  --spdx-version {1.2,2.0,1.0,2.1,2.2,2.3,1.1}, -sv {1.2,2.0,1.0,2.1,2.2,2.3,1.1}
                        Select the file version to set for exported spdx file. Defaults to version 2.3.

Spdx3 Options:
  Options for exporting spdx3 sbom documents.

  --spdx3-format {jsonld}, -s3f {jsonld}
                        Select the file output format to set for exported spdx3 file. Defaults to jsonld.
  --spdx3-version {3.0}, -s3v {3.0}
                        Select the file version to set for exported spdx3 file. Defaults to version 3.0.
```
