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
import inspect
import mimetypes
import os
import tempfile
import time
from pathlib import Path
from typing import AnyStr, Mapping, Optional
from datetime import datetime
from uuid import NAMESPACE_URL, UUID, uuid5

import semantic_version
from packageurl import PackageURL
from pdm_pfsc.logging import logger
from spdx_tools.spdx3.model import (
    CreationInfo,
    Relationship,
    RelationshipType,
    ProfileIdentifierType, Agent, Tool, IntegrityMethod, Hash, HashAlgorithm, RelationshipCompleteness,
    LifecycleScopeType,
)
from spdx_tools.spdx3.model.software import Sbom, SBOMType, Package, SoftwarePurpose, File, \
    SoftwareDependencyRelationship, SoftwareDependencyLinkType, DependencyConditionalityType
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.writer.json_ld.json_ld_writer import write_payload as write_jsonld
from spdx_tools.spdx3.validation.json_ld.shacl_validation import validate_against_shacl_from_file

from .base import ExporterBase, FormatAndVersionMixin

from typing import Callable, Union
from typing import IO

from ..dag import Node, UsageKind
from ..project import ComponentInfo, ToolInfo
from ..project.dataclasses import DEFAULT_GROUP_NAME, DEVELOPMENT_GROUP_NAME
from ..project.tools import create_module_info, create_self_info, create_pdm_info

_relationship_names_from_members: dict[RelationshipType, str] = {
    v: k for k, v in RelationshipType.__members__.items()
}

SHACL_FILE_PATH = Path(inspect.getfile(write_jsonld)).resolve().parent / "model.ttl"

if not mimetypes.inited:
    mimetypes.init()

class Spdx3Exporter(ExporterBase, FormatAndVersionMixin):
    _EXTENSIONS: Mapping[str, tuple[str, Callable[[Payload, str], None]]] = {
        "jsonld": (".spdx3.jsonld", write_jsonld),
    }
    _VERSIONS: Mapping[str, tuple[int, int]] = {
        "3.0": (3, 0),
    }

    SUPPORTED_FILE_FORMATS: frozenset[str] = frozenset(_EXTENSIONS.keys())
    SUPPORTED_VERSIONS: frozenset[str] = frozenset(_VERSIONS.keys())
    FORMAT_DESCRIPTION: str = "Experimental SPDX 3 support"
    DEFAULT_FILE_VERSION: str = "3.0"
    DEFAULT_FILE_FORMAT: str = "jsonld"
    SHORT_FORMAT_CODE: str = "s3"
    FORMAT_NAME: str = "spdx3"

    def __init__(self, project, *tools: ToolInfo) -> None:
        ExporterBase.__init__(self, project, *tools)
        FormatAndVersionMixin.__init__(self)

    @property
    def target_file_extension(self) -> str:
        return self._EXTENSIONS[self.file_format][0]

    def export(self, stream: IO[AnyStr]) -> None:
        spec_version: tuple[int, int] = self._VERSIONS[self.file_version]
        
        doc_id: UUID = self.__component_to_uuid(self.project)
        doc_name: str = Spdx3Exporter.__component_to_name(self.project)

        homepage: str = (self.project.homepage
                         or f"https://spdx-boms.1.0.0.127.nip.io/bom-namespaces/{self.project.name}")

        project_url: str = f"{homepage.rstrip('/')}/spdx/{self.file_version}/{doc_name}-{str(doc_id)}"  # TODO

        doc_name: str = Spdx3Exporter.__component_to_name(self.project)

        payload: Payload = Payload()

        creation_info = self._create_creation_info(payload, spec_version, project_url)

        elements, root_element = self._create_elements(project_url, payload, creation_info)

        sbom: Sbom = Sbom(
            spdx_id=Spdx3Exporter.__get_reference(project_url, doc_id),
            name=doc_name,
            summary=None,  # TODO
            description=None,  # TODO
            comment=None,
            sbom_type=[SBOMType.BUILD, SBOMType.SOURCE],
            context=None,
            namespaces=None,
            imports=None,
            element=elements,
            root_element=[root_element],
            creation_info=creation_info,
            extension=None,
            verified_using=None,
            external_reference=None,
            external_identifier=None,
        )

        payload.add_element(sbom)

        writer = self._EXTENSIONS[self.file_format][1]
        fd, name = tempfile.mkstemp(prefix=self.project.name, suffix="sbom", text=True)
        try:
            os.close(fd)
            os.remove(name)
            name = f"{name}{self.target_file_extension}"
            # .jsonld is added to file name automatically
            writer(payload, name.replace(".jsonld", ""))
            is_valid, _, error_text = validate_against_shacl_from_file(name, str(SHACL_FILE_PATH))
            if not is_valid:
                logger.error(error_text)
            with open(name, "r") as reader:
                for line in reader.readlines():
                    stream.write(line)
        finally:
            os.remove(name)

    def _create_creation_info(self, payload: Payload, spec_version: tuple[int, int], namespace: str):
        self_tool_info = create_self_info()
        pdm_tool_info = create_pdm_info()
        spdx_tool_info = create_module_info("spdx_tools")
        self_tool: Tool = Tool(
            spdx_id=Spdx3Exporter.__get_reference(
                namespace,
                Spdx3Exporter.__tool_to_uuid(self_tool_info)
            ),
            name=f"{self_tool_info.name}@{self_tool_info.vendor}",
        )
        pdm_tool: Tool = Tool(
            spdx_id=Spdx3Exporter.__get_reference(
                namespace,
                Spdx3Exporter.__tool_to_uuid(pdm_tool_info)
            ),
            name=f"{pdm_tool_info.name}@{pdm_tool_info.vendor}",
        )
        spdx_tool: Tool = Tool(
            spdx_id=Spdx3Exporter.__get_reference(
                namespace,
                Spdx3Exporter.__tool_to_uuid(spdx_tool_info)
            ),
            name=f"{spdx_tool_info.name}@{spdx_tool_info.vendor}",
        )
        payload.add_element(self_tool)
        payload.add_element(pdm_tool)
        payload.add_element(spdx_tool)
        creation_info: CreationInfo = CreationInfo(
            spec_version=semantic_version.Version(major=spec_version[0], minor=spec_version[1], patch=0),
            created=datetime.utcnow(),
            created_by=[
            ],
            profile=[
                ProfileIdentifierType.SOFTWARE
            ],
            created_using=[
                self_tool.spdx_id,
                pdm_tool.spdx_id,
                spdx_tool.spdx_id,
            ],
            comment=None,
        )
        self_tool.creation_info = creation_info
        pdm_tool.creation_info = creation_info
        spdx_tool.creation_info = creation_info
        creator_agent: Agent = Agent(
            spdx_id=Spdx3Exporter.__get_reference(
                namespace,
                Spdx3Exporter.__agent_uuid()
                ),
            creation_info=creation_info,
            name="pdm-sbom:Spdx3Exporter",
            summary="An SBOM creation tool for SPDX",
            description=None,
            comment=None,
            verified_using=None,
            external_identifier=None,
            extension=None,
            external_reference=None,
        )
        payload.add_element(creator_agent)
        creation_info.creator_agent = [creator_agent.spdx_id]
        return creation_info

    @staticmethod
    def __component_to_uuid(component: ComponentInfo) -> UUID:
        purl: PackageURL = component.get_package_url()

        unique_id: UUID = uuid5(NAMESPACE_URL, purl.to_string())

        return unique_id

    @staticmethod
    def __tool_to_uuid(tool: ToolInfo) -> UUID:
        purl: str = f"tools://{tool.vendor}/{tool.name}/{tool.version}"

        unique_id: UUID = uuid5(NAMESPACE_URL, purl)

        return unique_id

    @staticmethod
    def __agent_uuid() -> UUID:
        unique_id: UUID = uuid5(NAMESPACE_URL, "tools://pdm/plugins/pdm-sbom")

        return unique_id

    @staticmethod
    def __component_to_name(component: ComponentInfo) -> str:
        return f"{component.name}-{str(component.resolved_version) if component.resolved else 'UNKNOWN_VERSION'}"

    @staticmethod
    def __get_reference(namespace: str, identifier: UUID) -> str:
        return f"{namespace}#SPDXRef-{identifier}"

    @staticmethod
    def __component_to_uuid(component: ComponentInfo) -> UUID:
        purl: PackageURL = component.get_package_url()

        unique_id: UUID = uuid5(NAMESPACE_URL, purl.to_string())

        return unique_id

    def _create_elements(self, namespace: str, payload: Payload, creation_info: CreationInfo) -> tuple[list[str], str]:
        root_element_id: str = ""
        element_ids: list[str] = []
        for node in self.graph.nodes:
            Spdx3Exporter._get_files(namespace, payload, creation_info, node.component)
            Spdx3Exporter._get_relationships(namespace, payload, creation_info, node.component)
            element: Package = Package(
                spdx_id=Spdx3Exporter.__get_reference(
                    namespace,
                    Spdx3Exporter.__component_to_uuid(node.component)
                ),
                name=node.component.name,
                creation_info=creation_info,
                summary=None,  # TODO
                description=None,  # TODO
                comment=None,
                verified_using=None,
                extension=None,
                external_reference=None,
                external_identifier=None,
                originated_by=None,
                supplied_by=None,
                built_time=None,
                release_time=None,
                valid_until_time=None,
                standard=None,
                content_identifier=None,
                primary_purpose=SoftwarePurpose.LIBRARY,  # TODO
                additional_purpose=None,
                concluded_license=None,  # TODO
                declared_license=None,  # TODO
                copyright_text=None,  # TODO
                attribution_text=None,  # TODO
                package_version=str(node.component.resolved_version),
                download_location=None,  # TODO
                package_url=node.component.get_package_url().to_string(),
                homepage=None,  # TODO
                source_info=None,  # TODO
            )

            payload.add_element(element)

            if node.component == self.project:
                root_element_id = element.spdx_id

            element_ids.append(element.spdx_id)

        return element_ids, root_element_id

    @staticmethod
    def __get_file_ref(namespace: str, component: ComponentInfo, file_name: str) -> UUID:
        file_url = f"{namespace}/components/{component.name}/files/{file_name}"
        return uuid5(NAMESPACE_URL, file_url)

    @staticmethod
    def _get_files(namespace: str, payload: Payload, creation_info: CreationInfo, component: ComponentInfo) -> None:
        if len(component.files) == 0:
            return

        for file in component.files:
            c_type, _ = mimetypes.guess_type(file.file, False)
            file_instance: File = File(
                spdx_id=Spdx3Exporter.__get_reference(
                    namespace,
                    Spdx3Exporter.__get_file_ref(namespace, component, file.file)
                ),
                name=file.file,
                creation_info=creation_info,
                summary=None,
                description=None,
                comment=None,
                verified_using=[
                    Hash(
                        algorithm=HashAlgorithm.SHA256,  # TODO
                        hash_value=file.hash_value,
                        comment=None,
                    )
                ],
                external_reference=None,
                external_identifier=None,
                extension=None,
                originated_by=None,
                supplied_by=[Spdx3Exporter.__get_reference(
                    namespace,
                    Spdx3Exporter.__component_to_uuid(component)
                )],
                built_time=None,
                release_time=None,
                valid_until_time=None,
                standard=None,
                content_identifier=None,
                primary_purpose=SoftwarePurpose.ARCHIVE,
                additional_purpose=None,
                concluded_license=None,  # TODO
                declared_license=None,  # TODO,
                copyright_text=None,  # TODO,
                attribution_text=None,
                content_type=c_type,
            )
            payload.add_element(file_instance)

    @staticmethod
    def _get_relationships(namespace: str, payload: Payload, creation_info: CreationInfo, component: ComponentInfo) -> None:
        art_type: SoftwareDependencyLinkType = SoftwareDependencyLinkType.DYNAMIC
        for dependency_group in component.dependencies.keys():
            rel_type: RelationshipType = RelationshipType.RUNTIME_DEPENDENCY
            cond_type: DependencyConditionalityType = DependencyConditionalityType.REQUIRED
            ls_type: LifecycleScopeType = LifecycleScopeType.RUNTIME

            if dependency_group != DEFAULT_GROUP_NAME:
                if dependency_group != DEVELOPMENT_GROUP_NAME:
                    cond_type = DependencyConditionalityType.OPTIONAL
                else:
                    rel_type = RelationshipType.DEV_DEPENDENCY
                    ls_type = LifecycleScopeType.DEVELOPMENT

            related_components: list[str] = []
            for dependency in component.dependencies[dependency_group]:
                related_components.append(
                    Spdx3Exporter.__get_reference(
                        namespace,
                        Spdx3Exporter.__component_to_uuid(dependency.component)
                    )
                )

            if len(related_components) == 0:
                continue

            sw_rel: SoftwareDependencyRelationship = SoftwareDependencyRelationship(
                spdx_id=f"{namespace}/relationships/from/{component.name}",
                from_element=Spdx3Exporter.__get_reference(
                    namespace,
                    Spdx3Exporter.__component_to_uuid(component)
                ),
                relationship_type=rel_type,
                to=related_components,
                creation_info=creation_info,
                name=f"{component.name}-relationships-{dependency_group}",
                summary=None,
                description=None,
                comment=None,
                verified_using=None,
                external_reference=None,
                external_identifier=None,
                extension=None,
                completeness=RelationshipCompleteness.COMPLETE,
                start_time=None,
                end_time=None,
                scope=ls_type,
                software_linkage=art_type,
                conditionality=cond_type,
            )

            payload.add_element(sw_rel)
