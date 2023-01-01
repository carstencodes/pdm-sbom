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
from .data import Project
from .base import (
    ExporterBase,
    SupportsFileFormat,
    SupportsFileVersion,
    ToolInfo,
)
from .parser import ProjectBuilder
from .json import JsonExporter

try:
    from .cyclonedx import CycloneDXExporter

    HAS_CYCLONE_DX_EXPORT = True
except ImportError:
    HAS_CYCLONE_DX_EXPORT = False

try:
    from .spdx import SpdxExporter

    HAS_SPDX_EXPORT = True
except ImportError:
    HAS_SPDX_EXPORT = False

__all__ = [
    Project.__name__,
    ExporterBase.__name__,
    SupportsFileFormat.__name__,
    SupportsFileVersion.__name__,
    ToolInfo.__name__,
    ProjectBuilder.__name__,
    JsonExporter.__name__,
]

__FORMATS: dict[str, type[ExporterBase]] = {
    JsonExporter.FORMAT_NAME: JsonExporter,
}
__VERSIONS_PER_FILE_FORMAT = {}

if HAS_CYCLONE_DX_EXPORT:
    __all__.append(CycloneDXExporter.__name__)
    __FORMATS[CycloneDXExporter.FORMAT_NAME] = CycloneDXExporter
    __VERSIONS_PER_FILE_FORMAT[
        CycloneDXExporter.FORMAT_NAME
    ] = CycloneDXExporter.SUPPORTED_VERSIONS

if HAS_SPDX_EXPORT:
    __all__.append(SpdxExporter.__name__)
    __FORMATS[SpdxExporter.FORMAT_NAME] = SpdxExporter
    __VERSIONS_PER_FILE_FORMAT[
        SpdxExporter.FORMAT_NAME
    ] = SpdxExporter.SUPPORTED_VERSIONS


def get_exporter(file_format: str, project: Project, *tools: ToolInfo) -> ExporterBase:
    if file_format not in __FORMATS:
        raise KeyError(file_format)

    exporter_type = __FORMATS[file_format]
    return exporter_type(project, *tools)
