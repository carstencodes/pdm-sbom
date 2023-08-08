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

from boolean import Symbol as License
from packageurl import PackageURL  # type: ignore
from spdx_tools.spdx.model import (  # type: ignore
    Actor,
    ActorType,
    CreationInfo,
    Document,
    ExtractedLicensingInfo,
    Package,
    PackagePurpose,
    Relationship,
    RelationshipType,
    SpdxNoAssertion,
    SpdxNone,
    Version,
)
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document  # type: ignore
from spdx_tools.spdx.validation.validation_message import ValidationMessage  # type: ignore
from spdx_tools.spdx.writer.json.json_writer import write_document_to_stream as write_json  # type: ignore
from spdx_tools.spdx.writer.rdf.rdf_writer import write_document_to_stream as write_rdf  # type: ignore
from spdx_tools.spdx.writer.tagvalue.tagvalue_writer import write_document_to_stream as write_tag_value  # type: ignore
from spdx_tools.spdx.writer.xml.xml_writer import write_document_to_stream as write_xml  # type: ignore
from spdx_tools.spdx.writer.yaml.yaml_writer import write_document_to_stream as write_yaml  # type: ignore

from .base import ExporterBase, FormatAndVersionMixin, ToolInfo
from .data import Component
from .reencoder import ReEncoder
from .tools import create_module_info

_relationship_names_from_members: dict[RelationshipType, str] = {
    v: k for k, v in RelationshipType.__members__.items()
}

from typing import Callable, TypeAlias
from typing import IO, TextIO

def _write_json_document(document: Document, stream: IO[str]) -> None:
    write_json(document, stream, True, None, False)

def _write_xml_document(document: Document, stream: IO[str]) -> None:
    write_xml(document, stream, True, None, False)

def _write_yaml_document(document: Document, stream: IO[str]) -> None:
    write_yaml(document, stream, True, None, False)

def _write_tag_value_document(document: Document, stream: IO[str]) -> None:
    write_tag_value(document, stream, True, False)

def _write_rdf_document(document: Document, stream: IO[str]) -> None:
    write_rdf(document, stream, True, False)


DocumentWriter: TypeAlias = Callable[[Document, IO[str]], None]


class SpdxExporter(ExporterBase, FormatAndVersionMixin):
    _EXTENSIONS: Mapping[str, tuple[str, DocumentWriter]] = {
        "json": (".spdx.json", _write_json_document),
        "xml": (".spdx.xml", _write_xml_document),
        "rdf": (".spdx.rdf", _write_rdf_document),
        "rdf.xml": (".spdx.rdf.xml", _write_rdf_document),
        "yaml": (".spdx.yaml", _write_yaml_document),
        "yml": (".spdx.yml", _write_yaml_document),
        "tag": (".spdx.tag", _write_tag_value_document),
        "spdx": (".spdx", _write_tag_value_document),
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
        
        doc_id: UUID = self.component_to_uuid(self.project)

        doc_name: str = self.component_to_name(self.project)

        project_url: str = f"https://path/to/project/{doc_name}-{str(doc_id)}"  # TODO

        done: set[Component] = set()
        packages: list[Package] = []
        relationships: list[Relationship] = []
        extracted_licenses: list[ExtractedLicensingInfo] = []

        packages.append(self.component_to_package(self.project))

        relationships.append(
            Relationship(
                "SPDXRef-DOCUMENT",
                RelationshipType.DESCRIBES,
                f"SPDXRef-{self.component_to_uuid(self.project)}"
            )
        )

        for dependency in self.project.recurse_project(True, True, False):
            if dependency.component in done:
                continue
            package: Package = self.component_to_package(dependency.component)
            packages.append(package)
            done.add(dependency.component)

        for relationship in self.recurse_relationships(self.project):
            relationships.append(relationship)

        for component in self.project.development_dependencies:
            rel = Relationship(
                "SPDXRef-" + str(self.component_to_uuid(self.project)),
                RelationshipType.DEV_DEPENDENCY_OF,
                "SPDXRef-" + str(self.component_to_uuid(component)),
                None,
            )
            relationships.append(rel)

            for rel in self.recurse_relationships(component):
                relationships.append(rel)

        for group in self.project.optional_dependencies.values():
            for component in group:
                rel = Relationship(
                    "SPDXRef-" + str(self.component_to_uuid(self.project)),
                    RelationshipType.OPTIONAL_DEPENDENCY_OF,
                    "SPDXRef-" + str(self.component_to_uuid(component)),
                    None,
                )
                relationships.append(rel)

                for rel in self.recurse_relationships(component):
                    relationships.append(rel)

        creators: list[Actor] = []
        tool: ToolInfo = create_module_info("spdx-tools")
        creators.append(Actor(ActorType.TOOL, f"{tool.vendor} {tool.name} ({tool.version})", None))
        for tool in self.tools:
            creator: Actor = Actor(ActorType.TOOL, f"{tool.vendor} {tool.name} ({tool.version})")
            creators.append(creator)


        import datetime

        spdx_version: str = f"SPDX-{self.file_version}"
        creation_info: CreationInfo = CreationInfo(
            spdx_version,
            "SPDXRef-DOCUMENT",
            doc_name,
            project_url,
            creators,
            datetime.datetime.utcnow(),
            None,
            "CC0-1.0",
            [],
            None,
            None,
        )

        doc: Document = Document(
            creation_info,
            packages,
            [],  # files
            [],  # snippets
            [],  # annotations,
            relationships,
            extracted_licenses,
        )

        messages: List[ValidationMessage] = validate_full_spdx_document(doc, spdx_version)

        if messages:
            raise ValueError("\n".join([v.validation_message for v in messages]))

        writer: DocumentWriter = self._EXTENSIONS[self.file_format][1]

        with ReEncoder(stream) as target:
            writer(doc, target)

    def recurse_relationships(
        self,
        component: Component,
    ) -> Iterable[Relationship]:
        for dependency in component.dependencies:
            yield Relationship(
                "SPDXRef-" + str(self.component_to_uuid(component)),
                RelationshipType.DEPENDENCY_OF,
                "SPDXRef-" + str(self.component_to_uuid(dependency)),
                None,
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
    ) -> Actor | SpdxNoAssertion:
        if authors is None or len(authors) == 0:
            return SpdxNoAssertion()

        name: str = authors[0][0]
        mail: str = authors[0][1]
        if len(authors) == 1:
            # Assumption ...
            if "inc." in name.lower() or "ltd" in name.lower():
                return Actor(ActorType.ORGANIZATION, name, mail)
            if " and " in name.lower():
                return Actor(ActorType.ORGANIZATION, name, mail)
            if name.count(" ") == 0:
                return Actor(ActorType.ORGANIZATION, name, mail)

        return Actor(ActorType.PERSON, name, mail)

    def component_to_package(self, component: Component) -> Package:
        authors = self.get_creator(component.author)
        package: Package = Package(
            name=self.component_to_name(component),
            spdx_id="SPDXRef-" + str(self.component_to_uuid(component)),
            version=str(component.version),
            file_name=None,
            supplier=authors,
            originator=None,
            download_location=SpdxNone(),  # TODO
        )

        package.files_analyzed = False
        package.homepage = None
        package.verif_code = None
        package.checksums = []
        package.source_info = None
        if component.license_id is not None:
            license_name = component.license_id  # TODO
            package.license_declared = License(
                component.license_id,
            )
        else:
            package.license_declared = SpdxNone()
        package.license_declared = SpdxNone()
        package.license_comment = None
        package.licenses_from_files = [SpdxNoAssertion()]
        package.cr_text = SpdxNoAssertion()
        package.summary = None
        package.description = None
        package.verif_exc_files = []
        package.ext_pkg_refs = []
        package.attribution_text = None
        package.primary_package_purpose = PackagePurpose.LIBRARY  # TODO

        return package
