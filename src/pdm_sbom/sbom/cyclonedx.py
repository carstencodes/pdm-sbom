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
from typing import IO, AnyStr, Iterable, Mapping, cast

from cyclonedx.model import (  # type: ignore
    LicenseChoice,
    OrganizationalContact,
    OrganizationalEntity,
    Tool,
)
from cyclonedx.model.bom import Bom  # type: ignore
from cyclonedx.model.bom_ref import BomRef  # type: ignore
from cyclonedx.model.component import (  # type: ignore
    Component,
    ComponentScope,
    ComponentType,
)
from cyclonedx.output import (  # type: ignore
    OutputFormat,
    SchemaVersion,
)
from cyclonedx.output import get_instance as get_output_instance  # type: ignore
from cyclonedx.parser import BaseParser  # type: ignore
from packageurl import PackageURL  # type: ignore

from .base import ExporterBase, FormatAndVersionMixin, ToolInfo
from .data import Component as InnerComponent
from .data import ComponentUsage, Project


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
    }

    SUPPORTED_FILE_FORMATS: frozenset[str] = frozenset(_EXTENSIONS.keys())
    SUPPORTED_VERSIONS: frozenset[str] = frozenset(_VERSIONS.keys())
    FORMAT_NAME: str = "cyclonedx"

    def __init__(self, project, *tools: ToolInfo) -> None:
        ExporterBase.__init__(self, project, *tools)
        FormatAndVersionMixin.__init__(self)

    @property
    def target_file_extension(self) -> str:
        return self._EXTENSIONS[self.file_format][0]

    def export(self, stream: IO[AnyStr]) -> None:
        parser: _PdmExportParser = _PdmExportParser(self.project)
        bom: Bom = Bom.from_parser(parser=parser)
        for tool in self.tools:
            bom.metadata.tools.add(
                Tool(
                    vendor=tool.vendor,
                    name=tool.name,
                    version=tool.version,
                )
            )

        bom.metadata.authors = parser.authors_to_oc(self.project.author)
        bom.metadata.manufacture = parser.project_to_oe(self.project)
        bom.metadata.component = parser.component_to_cyclonedx(self.project)

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


class _PdmExportParser(BaseParser):
    def __init__(self, project: Project) -> None:
        super().__init__()
        scopes: dict[ComponentUsage, ComponentScope | None] = {
            ComponentUsage.Root: None,
            ComponentUsage.Direct: ComponentScope.REQUIRED,
            ComponentUsage.Optional: ComponentScope.OPTIONAL,
            ComponentUsage.Development: ComponentScope.EXCLUDED,
        }

        done: set[InnerComponent] = set()

        for child in project.recurse_project(True, True, False):
            if child.component in done:
                continue
            component = self.component_to_cyclonedx(
                child.component, scopes[child.usage]
            )
            self._components.append(component)
            done.add(child.component)

    def authors_to_oc(
        self, authors: list[tuple[str, str]]
    ) -> Iterable[OrganizationalContact]:
        for author in authors:
            name, email = author
            yield OrganizationalContact(name=name, email=email, phone=None)

    def project_to_oe(self, project: Project) -> OrganizationalEntity:
        return OrganizationalEntity(
            name=f"{project.name} Authors",
            urls=None,  # TODO
            contacts=self.authors_to_oc(project.author),
        )

    def license_to_license_choice(
        self, license_id: str | None
    ) -> Iterable[LicenseChoice]:
        if license_id is not None:
            yield LicenseChoice(license_expression=license_id)

    def component_to_cyclonedx(
        self, component: InnerComponent, scope: ComponentScope | None = None
    ) -> Component:
        purl: PackageURL = PackageURL(
            type="pypi", name=component.name, version=str(component.version)
        )
        dependencies = [self.component_to_bom_ref(c) for c in component.dependencies]

        result = Component(
            name=component.name,
            component_type=ComponentType.LIBRARY,  # TODO
            bom_ref=purl.to_string(),
            licenses=self.license_to_license_choice(component.license_id),
            purl=purl,
            version=str(component.version),
            scope=scope,
        )

        result.dependencies = dependencies

        return result

    def component_to_bom_ref(self, component: InnerComponent) -> BomRef:
        purl = PackageURL(
            type="pypi",
            name=component.name,
            version=str(component.version),
        )
        return BomRef(value=purl.to_string())
