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
from abc import ABC, abstractmethod
from typing import (
    Any,
    IO,
    AnyStr,
    Iterable,
    Mapping,
    Protocol,
    cast,
    runtime_checkable, Final,
)

from ..dag import Graph
from ..project import ProjectInfo, ToolInfo


@runtime_checkable
class SupportsFileFormat(Protocol):
    SUPPORTED_FILE_FORMATS: frozenset[str]
    DEFAULT_FILE_FORMAT: str

    @property
    def file_format(self) -> str:
        raise NotImplementedError()

    @file_format.setter
    def file_format(self, value: str) -> None:
        raise NotImplementedError()


@runtime_checkable
class SupportsFileVersion(Protocol):
    SUPPORTED_VERSIONS: frozenset[str]
    DEFAULT_FILE_VERSION: str

    @property
    def file_version(self) -> str:
        raise NotImplementedError()

    @file_version.setter
    def file_version(self, value: str) -> None:
        raise NotImplementedError()


class ExporterBase(ABC):
    FORMAT_NAME: str
    FORMAT_DESCRIPTION: str
    SHORT_FORMAT_CODE: str

    def __init__(self, graph: Graph, *tools: ToolInfo) -> None:
        self.__graph = graph
        self.__tools = list(tools)

    @property
    @abstractmethod
    def target_file_extension(self) -> str:
        raise NotImplementedError()

    @property
    def graph(self) -> Graph:
        return self.__graph

    @property
    def project(self) -> ProjectInfo:
        return self.__graph.root_node.project

    @property
    def tools(self) -> Iterable[ToolInfo]:
        yield from self.__tools

    @abstractmethod
    def export(self, stream: IO[str]) -> None:
        raise NotImplementedError()

    def _to_bytes(self, data_to_write: str) -> AnyStr:
        value: AnyStr = cast(
            AnyStr,
            cast(
                str,
                data_to_write,
            ).encode("utf-8"),
        )

        return value


class FormatAndVersionMixin:
    _EXTENSIONS: Mapping[str, Any] = {}
    _VERSIONS: Mapping[str, Any] = {}

    SUPPORTED_FILE_FORMATS: frozenset[str] = frozenset(_EXTENSIONS.keys())
    SUPPORTED_VERSIONS: frozenset[str] = frozenset(_VERSIONS.keys())
    DEFAULT_FILE_FORMAT: str
    DEFAULT_FILE_VERSION: str

    def __init__(self) -> None:
        formats = list(self.SUPPORTED_FILE_FORMATS)
        formats.sort()
        self.__file_format = formats[0]
        versions = list(self.SUPPORTED_VERSIONS)
        versions.sort()
        self.__file_version = versions[-1]

    @property
    def file_format(self) -> str:
        return self.__file_format

    @file_format.setter
    def file_format(self, value: str) -> None:
        if value not in self.SUPPORTED_FILE_FORMATS:
            raise ValueError(value)
        self.__file_format = value

    @property
    def file_version(self) -> str:
        return self.__file_version

    @file_version.setter
    def file_version(self, value: str) -> None:
        if value not in self.SUPPORTED_VERSIONS:
            raise ValueError(value)
        self.__file_version = value
