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
from collections import namedtuple
from typing import Sequence

from .base import (
    ExporterBase,
    SupportsFileFormat,
    SupportsFileVersion,
)
from .json import JsonExporter
from ..project import ToolInfo as _ToolInfo
from ..dag import Graph as _Graph

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

try:
    from .spdx3 import Spdx3Exporter

    HAS_SPDX3_EXPORT = True
except ImportError as e:
    print(e)
    HAS_SPDX3_EXPORT = False

try:
    from .buildinfo import BuildInfoExporter

    HAS_BUILD_INFO_EXPORT = True
except ImportError:
    HAS_BUILD_INFO_EXPORT = False


__all__ = [
    ExporterBase.__name__,
    SupportsFileFormat.__name__,
    SupportsFileVersion.__name__,
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

if HAS_SPDX3_EXPORT:
    __all__.append(Spdx3Exporter.__name__)
    __FORMATS[Spdx3Exporter.FORMAT_NAME] = Spdx3Exporter
    __VERSIONS_PER_FILE_FORMAT[
        Spdx3Exporter.FORMAT_NAME
    ] = Spdx3Exporter.SUPPORTED_VERSIONS

if HAS_BUILD_INFO_EXPORT:
    __all__.append(BuildInfoExporter.__name__)
    __FORMATS[BuildInfoExporter.FORMAT_NAME] = BuildInfoExporter

_exporter_description = namedtuple("ExporterDescription",
                                   ["name", "description", "formats",
                                    "versions", "default_format", "default_version", "short_format_code"])


def get_exporter(file_format: str, graph: _Graph, *tools: _ToolInfo) -> ExporterBase:
    if file_format not in __FORMATS:
        raise KeyError(file_format)

    exporter_type = __FORMATS[file_format]
    return exporter_type(graph, *tools)


def get_exporters() -> Sequence[_exporter_description]:
    return [
        _exporter_description(
            f.FORMAT_NAME,
            f.FORMAT_DESCRIPTION,
            f.SUPPORTED_FILE_FORMATS if isinstance(f, SupportsFileFormat) else frozenset(),
            f.SUPPORTED_VERSIONS if isinstance(f, SupportsFileVersion) else frozenset(),
            f.DEFAULT_FILE_FORMAT if isinstance(f, SupportsFileFormat) else "",
            f.DEFAULT_FILE_VERSION if isinstance(f, SupportsFileVersion) else "",
            f.SHORT_FORMAT_CODE)
        for f in __FORMATS.values()
    ]
