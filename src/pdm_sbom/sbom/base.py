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
    runtime_checkable,
)

from .data import Project


@runtime_checkable
class SupportsFileFormat(Protocol):
    SUPPORTED_FILE_FORMATS: frozenset[str]

    @property
    def file_format(self) -> str:
        raise NotImplementedError()

    @file_format.setter
    def file_format(self, value: str) -> None:
        raise NotImplementedError()


@runtime_checkable
class SupportsFileVersion(Protocol):
    SUPPORTED_VERSIONS: frozenset[str]

    @property
    def file_version(self) -> str:
        raise NotImplementedError()

    @file_version.setter
    def file_version(self, value: str) -> None:
        raise NotImplementedError()


class ToolInfo:
    def __init__(self, vendor: str, name: str, version: str) -> None:
        self.__vendor = vendor
        self.__name = name
        self.__version = version

    @property
    def vendor(self) -> str:
        return self.__vendor

    @property
    def name(self) -> str:
        return self.__name

    @property
    def version(self) -> str:
        return self.__version


class ExporterBase(ABC):
    FORMAT_NAME: str

    def __init__(self, project: Project, *tools: ToolInfo) -> None:
        self.__project = project
        self.__tools = list(tools)

    @property
    @abstractmethod
    def target_file_extension(self) -> str:
        raise NotImplementedError()

    @property
    def project(self) -> Project:
        return self.__project

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
