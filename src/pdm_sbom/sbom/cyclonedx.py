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
from typing import IO, AnyStr, Iterable, Mapping, cast, Optional, ClassVar, Union, Final
from uuid import UUID, uuid5, NAMESPACE_URL

from cyclonedx.model import (  # type: ignore
    OrganizationalContact,
    OrganizationalEntity,
    Tool, ExternalReference, ExternalReferenceType, XsUri, HashType,
)
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import (
    Component,
    ComponentScope,
    ComponentType,
)
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.license import LicenseExpression, DisjunctiveLicense
from cyclonedx.output import (
    OutputFormat,
    SchemaVersion,
)
from cyclonedx.output import make_outputter as get_output_instance
from packageurl import PackageURL

from .base import ExporterBase, FormatAndVersionMixin, ToolInfo
from ..dag import UsageKind, Graph
from ..project import ProjectInfo, AuthorInfo, ComponentInfo, LicenseInfo, create_self_info, create_pdm_info
from ..project.tools import create_module_info
from datetime import datetime


class CycloneDXExporter(ExporterBase, FormatAndVersionMixin):
    _EXTENSIONS: Mapping[str, tuple[str, OutputFormat]] = {
        "json": (".cyclonedx.json", OutputFormat.JSON),
        "xml": (".cyclonedx.xml", OutputFormat.XML),
    }
    _VERSIONS: Mapping[str, SchemaVersion] = {
        "1.0": SchemaVersion.V1_0,
        "1.1": SchemaVersion.V1_1,
        "1.2": SchemaVersion.V1_2,
        "1.3": SchemaVersion.V1_3,
        "1.4": SchemaVersion.V1_4,
        "1.5": SchemaVersion.V1_5,
    }

    SUPPORTED_FILE_FORMATS: frozenset[str] = frozenset(_EXTENSIONS.keys())
    SUPPORTED_VERSIONS: frozenset[str] = frozenset(_VERSIONS.keys())
    DEFAULT_FILE_FORMAT: Final[str] = "json"
    DEFAULT_FILE_VERSION: Final[str] = "1.5"
    FORMAT_NAME: str = "cyclonedx"
    SHORT_FORMAT_CODE: str = "c"
    FORMAT_DESCRIPTION = f"CycloneDX file format - "\
                         f"supported versions: {', '.join(SUPPORTED_VERSIONS)} - "\
                         f"supported formats: {', '.join(SUPPORTED_FILE_FORMATS)}"

    def __init__(self, project, *tools: ToolInfo) -> None:
        ExporterBase.__init__(self, project, *tools)
        FormatAndVersionMixin.__init__(self)

    @property
    def target_file_extension(self) -> str:
        return self._EXTENSIONS[self.file_format][0]

    def export(self, stream: IO[AnyStr]) -> None:
        builder: _PdmBuilder = _PdmBuilder(self.graph)
        bom: Bom = builder.build()

        if not bom.validate():
            pass  # TODO result is always true or an exception

        output = get_output_instance(
            bom=bom,
            output_format=self._EXTENSIONS[self.file_format][1],
            schema_version=self._VERSIONS[self.file_version],
        )

        data: str = output.output_as_string()
        data_to_write: AnyStr = cast(AnyStr, data)
        if "b" in stream.mode:
            data_to_write = cast(AnyStr, self._to_bytes(cast(str, data_to_write)))
        stream.write(data_to_write)


class _PdmBuilder:
    scopes: ClassVar[dict[UsageKind, Optional[ComponentScope]]] = {
            UsageKind.ROOT: None,
            UsageKind.REQUIRED: ComponentScope.REQUIRED,
            UsageKind.OPTIONAL: ComponentScope.OPTIONAL,
            UsageKind.DEVELOPMENT: ComponentScope.EXCLUDED,
            UsageKind.UNUSED: ComponentScope.EXCLUDED,
        }

    def __init__(self, graph: Graph) -> None:
        self.__project: ProjectInfo = graph.root_node.project
        self.__graph: Graph = graph

    def build(self) -> Bom:
        return Bom(
            components=self.__build_components(),
            services=(),
            external_references=self.__get_external_references(),
            serial_number=self.__get_serial_number(),
            version=1,
            metadata=self.__get_metadata(),
            dependencies=self.__get_dependencies(),
            vulnerabilities=()
        )

    @staticmethod
    def authors_to_oc(
        authors: Sequence[AuthorInfo]
    ) -> Iterable[OrganizationalContact]:
        for author in authors:
            yield OrganizationalContact(name=author.name, email=author.email, phone=None)

    @staticmethod
    def project_to_oe(project: ProjectInfo) -> OrganizationalEntity:
        return OrganizationalEntity(
            name=f"{project.name} Authors",
            urls=None,  # TODO
            contacts=_PdmBuilder.authors_to_oc(project.authors),
        )

    @staticmethod
    def license_to_license_choice(
        _: LicenseInfo
    ) -> Iterable[Union[LicenseExpression, DisjunctiveLicense]]:
        return ()

    @staticmethod
    def component_to_cyclonedx(
        component: ComponentInfo, scope: Optional[ComponentScope] = None, group: Optional[str] = None
    ) -> Component:
        purl: PackageURL = component.get_package_url()

        result = Component(
            name=component.name,
            type=ComponentType.LIBRARY,  # TODO
            bom_ref=purl.to_string(),
            licenses=_PdmBuilder.license_to_license_choice(component.license),
            mime_type=None,
            purl=purl,
            version=str(component.resolved_version) if component.resolved else None,
            scope=scope,
            supplier=None,  # TODO
            author=None,  # TODO
            publisher=None,  # TODO
            group=group,
            hashes=(),
            copyright=None,  # TODO
            external_references=_PdmBuilder.__get_external_references_for(component),
            properties=(),
            release_notes=None,
            cpe=None,
            swid=None,
            pedigree=None,
            components=(),
            evidence=None,  # TODO
            modified=False,
        )

        return result

    @staticmethod
    def __component_to_bom_ref(component: ComponentInfo) -> BomRef:
        purl = component.get_package_url()
        return BomRef(value=purl.to_string())

    @staticmethod
    def __get_external_references_for(component: ComponentInfo) -> Iterable[ExternalReference]:
        for file in component.files:
            yield ExternalReference(
                comment=None,
                type=ExternalReferenceType.DISTRIBUTION,
                url=XsUri(f"cyclonedx-files://{component.name}/files{file.file}"),
                hashes=(
                    HashType.from_composite_str(file.hash),
                )
            )

    @staticmethod
    def __get_tools(*tools: ToolInfo) -> Iterable[Tool]:
        for tool in tools:
            yield Tool(
                name=tool.name,
                vendor=tool.vendor,
                version=str(tool.version),
            )

    def __get_metadata(self) -> BomMetaData:
        return BomMetaData(
            component=_PdmBuilder.component_to_cyclonedx(self.__project, None, None),
            tools=_PdmBuilder.__get_tools(
                create_self_info(),
                create_pdm_info(),
                create_module_info("cyclonedx_bom"),
                create_module_info("cyclonedx_python_lib"),
            ),
            authors=_PdmBuilder.authors_to_oc(self.__project.authors),
            manufacture=_PdmBuilder.project_to_oe(self.__project),
            supplier=None,
            licenses=None,  # TODO
            properties=(),
            timestamp=datetime.utcnow()
        )

    def __get_serial_number(self) -> UUID:
        return uuid5(NAMESPACE_URL, f"cyclonedx://{self.__project.name}/{self.__project.resolved_version}")

    def __build_components(self) -> Iterable[Component]:
        yield _PdmBuilder.component_to_cyclonedx(self.__project, None, None)
        for node in self.__graph.nodes:
            if node == self.__graph.root_node:
                continue
            cs: Optional[ComponentScope] = _PdmBuilder.scopes.get(node.usage, None)
            yield _PdmBuilder.component_to_cyclonedx(node.component, cs, node.group)

    def __get_external_references(self) -> Iterable[ExternalReference]:
        return _PdmBuilder.__get_external_references_for(self.__project)

    def __get_dependencies(self) -> Iterable[Dependency]:
        for node in self.__graph.nodes:
            yield Dependency(
                ref=_PdmBuilder.__component_to_bom_ref(node.component),
                dependencies=_PdmBuilder.__get_dependencies_for(node.component)
            )

    @staticmethod
    def __get_dependencies_for(component: ComponentInfo) -> Iterable[Dependency]:
        for _, dependency in component.all_dependencies():
            yield Dependency(
                ref=_PdmBuilder.__component_to_bom_ref(dependency.component),
                dependencies=_PdmBuilder.__get_dependencies_for(dependency.component)
            )
