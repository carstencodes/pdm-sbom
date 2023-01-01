#
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2022-2023 Carsten Igel.
#
# This file is part of pdm-sbom
# (see https://github.com/carstencodes/pdm-sbom).
#
# This file is published using the MIT license.
# Refer to LICENSE for more information
#
from types import ModuleType
from typing import IO, AnyStr, Iterable, Mapping, cast
from uuid import NAMESPACE_URL, UUID, uuid5

from packageurl import PackageURL  # type: ignore
from spdx.config import LICENSE_LIST_VERSION, LICENSE_MAP  # type: ignore
from spdx.creationinfo import (  # type: ignore
    Creator,
    Organization,
    Person,
    Tool,
)
from spdx.document import Document  # type: ignore
from spdx.license import License  # type: ignore
from spdx.package import Package, PackagePurpose  # type: ignore
from spdx.parsers.loggers import ErrorMessages  # type: ignore
from spdx.relationship import Relationship, RelationshipType  # type: ignore
from spdx.utils import NoAssert, SPDXNone  # type: ignore
from spdx.version import Version  # type: ignore
from spdx.writers import json, rdf, tagvalue, xml, yaml  # type: ignore
from spdx.writers.tagvalue import InvalidDocumentError  # type: ignore

from .base import ExporterBase, FormatAndVersionMixin, ToolInfo
from .data import Component
from .reencoder import ReEncoder
from .tools import create_module_info

_relationship_names_from_members: dict[RelationshipType, str] = {
    v: k for k, v in RelationshipType.__members__.items()
}


class SpdxExporter(ExporterBase, FormatAndVersionMixin):
    _EXTENSIONS: Mapping[str, tuple[str, ModuleType, bool]] = {
        "json": (".spdx.json", json, False),
        "xml": (".spdx.xml", xml, False),
        "rdf": (".spdx.rdf", rdf, True),
        "rdf.xml": (".spdx.rdf.xml", rdf, True),
        "yaml": (".spdx.yaml", yaml, True),
        "yml": (".spdx.yml", yaml, True),
        "tag": (".spdx.tag", tagvalue, True),
        "spdx": (".spdx", tagvalue, True),
    }
    _VERSIONS: Mapping[str, tuple[int, int]] = {
        "1.0": (1, 0),
        "1.1": (1, 1),
        "1.2": (1, 2),
        "2.0": (2, 0),
        "2.1": (2, 1),
        "2.2": (2, 2),
        "2.3": (2, 3),
    }

    SUPPORTED_FILE_FORMATS: frozenset[str] = frozenset(_EXTENSIONS.keys())
    SUPPORTED_VERSIONS: frozenset[str] = frozenset(_VERSIONS.keys())
    FORMAT_NAME: str = "spdx"

    def __init__(self, project, *tools: ToolInfo) -> None:
        ExporterBase.__init__(self, project, *tools)
        FormatAndVersionMixin.__init__(self)

    @property
    def target_file_extension(self) -> str:
        return self._EXTENSIONS[self.file_format][0]

    def export(self, stream: IO[AnyStr]) -> None:
        spec_version: Version = self._VERSIONS[self.file_version]
        spec_license: License = License(
            LICENSE_MAP["CC0-1.0"],
            "CC0-1.0",
        )

        doc_id: UUID = self.component_to_uuid(self.project)

        doc_name: str = self.component_to_name(self.project)

        llv = LICENSE_LIST_VERSION
        ll_version: str = f"{llv.major}.{llv.minor}"
        project_url: str = f"https://path/to/project/{doc_name}-{str(doc_id)}"  # TODO

        doc: Document = Document(
            version=spec_version,
            data_license=spec_license,
            name=doc_name,
            spdx_id=str(doc_id) + "SPDXRef-DOCUMENT",
            namespace=project_url,
            license_list_version=ll_version,
            comment=None,
            package=self.component_to_package(self.project),
        )

        done: set[Component] = set()
        for dependency in self.project.recurse_project(True, True, False):
            if dependency.component in done:
                continue
            package: Package = self.component_to_package(dependency.component)
            doc.add_package(package)
            done.add(dependency.component)

        for relationship in self.recurse_relationships(self.project):
            doc.add_relationship(relationship)

        for component in self.project.development_dependencies:
            relationship_text: str = self.relate(
                component,
                self.project,
                RelationshipType.DEV_DEPENDENCY_OF,
            )

            rel: Relationship = Relationship(
                relationship=relationship_text,
                relationship_comment=None,
            )
            doc.add_relationship(rel)

            for rel in self.recurse_relationships(component):
                doc.add_relationship(rel)

        for group in self.project.optional_dependencies.values():
            for component in group:
                relationship_text = self.relate(
                    component,
                    self.project,
                    RelationshipType.OPTIONAL_DEPENDENCY_OF,
                )
                rel = Relationship(
                    relationship=relationship_text,
                    relationship_comment=None,
                )
                doc.add_relationship(rel)

                for rel in self.recurse_relationships(component):
                    doc.add_relationship(rel)

        doc.creation_info.add_creator(create_module_info("spdx-tools"))
        for tool in self.tools:
            creator: Tool = Tool(f"{tool.vendor} {tool.name} ({tool.version})")
            doc.creation_info.add_creator(creator)

        doc.creation_info.set_created_now()

        messages = ErrorMessages()
        messages = doc.validate(messages)
        if messages:
            raise InvalidDocumentError(messages)

        target_module: ModuleType = self._EXTENSIONS[self.file_format][1]

        assert "write_document" in dir(target_module)

        with ReEncoder(stream) as target:
            target_module.write_document(doc, target, validate=False)

    def relate(
        self,
        component_from: Component,
        component_to: Component,
        what: RelationshipType,
    ) -> str:
        from_id: UUID = self.component_to_uuid(component_from)
        to_id: UUID = self.component_to_uuid(component_to)

        what_as_str: str = _relationship_names_from_members[what]

        return f"{str(from_id)} {what_as_str} {str(to_id)}"

    def recurse_relationships(
        self,
        component: Component,
    ) -> Iterable[Relationship]:
        for dependency in component.dependencies:
            yield Relationship(
                self.relate(
                    dependency,
                    component,
                    RelationshipType.DEPENDENCY_OF,
                )
            )

            yield from self.recurse_relationships(dependency)

    def component_to_uuid(self, component: Component) -> UUID:
        purl: PackageURL = PackageURL(
            type="pypi",
            name=component.name,
            version=str(component.version),
        )

        unique_id: UUID = uuid5(NAMESPACE_URL, purl.to_string())

        return unique_id

    def component_to_name(self, component: Component) -> str:
        return f"{component.name}-{str(component.version)}"

    def get_creator(
        self,
        authors: list[tuple[str, str]] | None,
    ) -> Creator | NoAssert:
        if authors is None or len(authors) == 0:
            return NoAssert()

        name: str = authors[0][0]
        mail: str = authors[0][1]
        if len(authors) == 1:
            # Assumption ...
            if "inc." in name.lower() or "ltd" in name.lower():
                return Organization(name, mail)
            if " and " in name.lower():
                return Organization(name, mail)
            if name.count(" ") == 0:
                return Organization(name, mail)

        return Person(name, mail)

    def component_to_package(self, component: Component) -> Package:
        authors = self.get_creator(component.author)
        package: Package = Package(
            name=self.component_to_name(component),
            spdx_id=str(self.component_to_uuid(component)),
            version=str(component.version),
            file_name=None,
            supplier=authors,
            originator=None,
            download_location="",  # TODO
        )

        package.files_analyzed = False
        package.homepage = None
        package.verif_code = None
        package.checksums = {}
        package.source_info = None
        if component.license_id is not None:
            license_name = LICENSE_MAP.get(component.license_id)
            package.conc_lics = License(
                license_name,
                component.license_id,
            )
        else:
            package.conc_lics = SPDXNone()
        package.license_declared = SPDXNone()
        package.license_comment = None
        package.licenses_from_files = [NoAssert()]
        package.cr_text = NoAssert()
        package.summary = None
        package.description = None
        package.verif_exc_files = []
        package.ext_pkg_refs = []
        package.attribution_text = None
        package.primary_package_purpose = PackagePurpose.LIBRARY  # TODO

        return package
