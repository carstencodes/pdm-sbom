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
from collections.abc import Sequence
from typing import AnyStr, Iterable, Mapping, Final
from datetime import datetime
from uuid import NAMESPACE_URL, UUID, uuid5

from packageurl import PackageURL
from spdx_tools.spdx.model import (
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
    ExternalPackageRef, ExternalPackageRefCategory, File, Checksum, ChecksumAlgorithm,
)
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.validation.validation_message import ValidationMessage
from spdx_tools.spdx.writer.json.json_writer import write_document_to_stream as write_json
from spdx_tools.spdx.writer.rdf.rdf_writer import write_document_to_stream as write_rdf
from spdx_tools.spdx.writer.tagvalue.tagvalue_writer import write_document_to_stream as write_tag_value
from spdx_tools.spdx.writer.xml.xml_writer import write_document_to_stream as write_xml
from spdx_tools.spdx.writer.yaml.yaml_writer import write_document_to_stream as write_yaml

from .base import ExporterBase, FormatAndVersionMixin

from typing import Callable, TypeAlias, Union
from typing import IO, TextIO

from ..dag import Node, UsageKind
from ..project import ComponentInfo, ToolInfo, AuthorInfo
from ..project.tools import create_module_info


_relationship_names_from_members: dict[RelationshipType, str] = {
    v: k for k, v in RelationshipType.__members__.items()
}


def _write_json_document(document: Document, stream: IO[str]) -> None:
    write_json(document, stream, True, None, False)


def _write_xml_document(document: Document, stream: IO[str]) -> None:
    write_xml(document, stream, True, None, False)


def _write_yaml_document(document: Document, stream: IO[str]) -> None:
    write_yaml(document, stream, True, None, False)


def _write_tag_value_document(document: Document, stream: TextIO) -> None:
    write_tag_value(document, stream, True, False)


def _write_rdf_document(document: Document, stream: IO[bytes]) -> None:
    write_rdf(document, stream, True, False)


StringDocumentWriter: TypeAlias = Callable[[Document, IO[str]], None]
TextDocumentWriter: TypeAlias = Callable[[Document, TextIO], None]
BytesDocumentWriter: TypeAlias = Callable[[Document, IO[bytes]], None]

DocumentWriter: TypeAlias = Union[StringDocumentWriter, TextDocumentWriter, BytesDocumentWriter]


class SpdxExporter(ExporterBase, FormatAndVersionMixin):
    _EXTENSIONS: Mapping[str, tuple[str, DocumentWriter]] = {
        "json": (".spdx.json", _write_json_document),
        "xml": (".spdx.xml", _write_xml_document),
        "rdf": (".spdx.rdf", _write_rdf_document),
        "rdf-xml": (".spdx.rdf.xml", _write_rdf_document),
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
    DEFAULT_FILE_FORMAT: Final[str] = "json"
    DEFAULT_FILE_VERSION: Final[str] = "2.3"
    SHORT_FORMAT_CODE: str = "s"
    FORMAT_NAME: str = "spdx"
    FORMAT_DESCRIPTION: str = f"SPDX file format - "\
                              f"supported versions: {', '.join(SUPPORTED_VERSIONS)} - "\
                              f"supported formats: {', '.join(SUPPORTED_FILE_FORMATS)}"

    def __init__(self, project, *tools: ToolInfo) -> None:
        ExporterBase.__init__(self, project, *tools)
        FormatAndVersionMixin.__init__(self)

    @property
    def target_file_extension(self) -> str:
        return self._EXTENSIONS[self.file_format][0]

    def export(self, stream: IO[AnyStr]) -> None:
        spec_version: tuple[int, int] = self._VERSIONS[self.file_version]
        
        doc_id: UUID = self.__component_to_uuid(self.project)

        doc_name: str = SpdxExporter.__component_to_name(self.project)

        homepage: str = (self.project.homepage
                         or f"https://spdx-boms.1.0.0.127.nip.io/bom-namespaces/{self.project.name}")
        project_url: str = f"{homepage.rstrip('/')}/spdx/{self.file_version}/{doc_name}-{str(doc_id)}"  # TODO

        packages: list[Package] = []
        relationships: list[Relationship] = []
        extracted_licenses: list[ExtractedLicensingInfo] = []

        packages.append(SpdxExporter.__component_to_package(self.project))

        relationships.append(
            Relationship(
                "SPDXRef-DOCUMENT",
                RelationshipType.DESCRIBES,
                SpdxExporter.__get_reference(self.__component_to_uuid(self.project))
            )
        )

        for node in self.graph.nodes:
            if node == self.graph.root_node:
                continue
            package: Package = SpdxExporter.__component_to_package(node.component)
            packages.append(package)

        for relationship in self.__recurse_relationships():
            relationships.append(relationship)

        creators: list[Actor] = []
        tool: ToolInfo = create_module_info("spdx-tools")
        creators.append(Actor(ActorType.TOOL, f"{tool.vendor} {tool.name} ({tool.version})", None))
        for tool in self.tools:
            creator: Actor = Actor(ActorType.TOOL, f"{tool.vendor} {tool.name} ({tool.version})")
            creators.append(creator)

        spdx_version: str = f"SPDX-{spec_version[0]}.{spec_version[1]}"
        creation_info: CreationInfo = CreationInfo(
            spdx_version,
            "SPDXRef-DOCUMENT",
            doc_name,
            project_url,
            creators,
            datetime.utcnow(),
            None,
            "CC0-1.0",
            [],
            None,
            None,
        )

        doc: Document = Document(
            creation_info,
            packages,
            self.__get_files(),  # files
            [],  # snippets
            [],  # annotations,
            relationships,
            extracted_licenses,
        )

        messages: list[ValidationMessage] = validate_full_spdx_document(doc, spdx_version)

        if messages:
            raise ValueError("\n".join([v.validation_message for v in messages]))

        writer: DocumentWriter = self._EXTENSIONS[self.file_format][1]
        writer(doc, stream)

    def __recurse_relationships(
        self,
    ) -> Iterable[Relationship]:
        for node in self.graph.nodes:
            for related in self.graph[node]:
                yield SpdxExporter.__create_relationship(node, related)
            for reference_file in node.component.files:
                yield Relationship(
                    spdx_element_id=SpdxExporter.__get_reference(SpdxExporter.__component_to_uuid(node.component)),
                    comment=None,
                    relationship_type=RelationshipType.CONTAINED_BY,
                    related_spdx_element_id=SpdxExporter.__get_file_ref(node.component.name, reference_file.file)
                )

    def __get_files(self) -> list[File]:
        def __get_checksum_algorithm(value: str) -> ChecksumAlgorithm:
            if value == "sha256":
                return ChecksumAlgorithm.SHA256

            raise ValueError(f"Invalid checksum algorithm {value}")

        SPDX_NONE: Final[str] = "DEADC0DED00D2BADDEFEC8EDDEADF00DDEADFA11".lower()

        result: list[File] = []
        for node in self.graph.nodes:
            for referenced_file in node.component.files:
                file: File = File(
                    name=referenced_file.file,
                    spdx_id=SpdxExporter.__get_file_ref(node.component.name, referenced_file.file),
                    checksums=[
                        Checksum(
                            algorithm=__get_checksum_algorithm(referenced_file.hash_algorithm),
                            value=referenced_file.hash_value
                        ),
                        Checksum(
                            algorithm=ChecksumAlgorithm.SHA1,
                            value=SPDX_NONE,
                        )
                    ]
                )

                result.append(file)
        return result

    @staticmethod
    def __component_to_uuid(component: ComponentInfo) -> UUID:
        purl: PackageURL = component.get_package_url()

        unique_id: UUID = uuid5(NAMESPACE_URL, purl.to_string())

        return unique_id

    @staticmethod
    def __component_to_name(component: ComponentInfo) -> str:
        return f"{component.name}-{str(component.resolved_version) if component.resolved else 'UNKNOWN_VERSION'}"

    @staticmethod
    def __get_creator(
        authors: Sequence[AuthorInfo],
    ) -> Union[Actor, SpdxNoAssertion]:
        if len(authors) == 0:
            return SpdxNoAssertion()

        name: str = authors[0].name
        description: str = authors[0].description or ""
        mail: str = authors[0].email or ""
        if len(authors) == 1:
            # Assumption ...
            if "inc." in description.lower() or "ltd" in description.lower():
                return Actor(ActorType.ORGANIZATION, name, mail)
            if " and " in description.lower():
                return Actor(ActorType.ORGANIZATION, name, mail)
            if name.count(" ") == 0:
                return Actor(ActorType.ORGANIZATION, name, mail)

        return Actor(ActorType.PERSON, name, mail)

    @staticmethod
    def __component_to_package(component: ComponentInfo) -> Package:
        authors = SpdxExporter.__get_creator(component.authors)
        package: Package = Package(
            name=SpdxExporter.__component_to_name(component),
            spdx_id=SpdxExporter.__get_reference(SpdxExporter.__component_to_uuid(component)),
            version=str(component.resolved_version) if component.resolved_version else None,
            file_name=None,
            supplier=authors,
            originator=None,
            homepage=component.homepage if component.homepage is not None else SpdxNone(),
            external_references=[
              ExternalPackageRef(
                category=ExternalPackageRefCategory.PACKAGE_MANAGER,
                reference_type="purl",
                locator=component.get_package_url().to_string(),
                comment=None
              )
            ],
            download_location=SpdxNone(),  # TODO
        )

        package.files_analyzed = False
        package.homepage = None
        package.verif_code = None
        package.checksums = []
        package.source_info = None
        if component.license is not None:
            package.license_declared = SpdxNoAssertion()  # TODO
        else:
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

    @staticmethod
    def __create_relationship(from_node: Node, to_node: Node) -> Relationship:
        return Relationship(
            spdx_element_id=SpdxExporter.__get_reference(SpdxExporter.__component_to_uuid(from_node.component)),
            relationship_type=SpdxExporter.__get_relationship_type(from_node.usage, to_node.usage),
            related_spdx_element_id=SpdxExporter.__get_reference(SpdxExporter.__component_to_uuid(to_node.component)),
            comment=None,
        )

    @staticmethod
    def __get_reference(identifier: UUID) -> str:
        return "SPDXRef-" + str(identifier)

    @staticmethod
    def __get_relationship_type(from_usage: UsageKind, to_usage: UsageKind) -> RelationshipType:
        if from_usage == UsageKind.ROOT:
            return SpdxExporter.__get_concrete_relationship_type(to_usage)

        return SpdxExporter.__get_concrete_relationship_type(UsageKind.REQUIRED)

    @staticmethod
    def __get_concrete_relationship_type(usage: UsageKind) -> RelationshipType:
        if usage == UsageKind.REQUIRED:
            return RelationshipType.DEPENDENCY_OF
        elif usage == UsageKind.OPTIONAL:
            return RelationshipType.OPTIONAL_DEPENDENCY_OF
        elif usage == UsageKind.DEVELOPMENT:
            return RelationshipType.DEV_DEPENDENCY_OF

        return RelationshipType.OTHER

    @staticmethod
    def __get_file_ref(component_name: str, file_name: str) -> str:
        file_url = f"spdx-files:///{component_name}/files/{file_name}"
        return SpdxExporter.__get_reference(uuid5(NAMESPACE_URL, file_url))
