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
from dataclasses import asdict
from json import JSONEncoder, dumps
from typing import IO, Any, AnyStr, cast

from packaging.version import Version

from .base import ExporterBase


class JsonExporter(ExporterBase):
    FORMAT_NAME: str = "json"
    SHORT_FORMAT_CODE: str = "j"
    FORMAT_DESCRIPTION: str = "Pure JSON Serialization - unstable"

    @property
    def target_file_extension(self) -> str:
        return ".pdm-sbom.json"

    def export(self, stream: IO[AnyStr]) -> None:
        data = asdict(self.project)
        data_to_write: str = dumps(
            data,
            cls=_VersionSupportingEncoder,
        )
        if "b" in stream.mode:
            data_to_write = cast(
                AnyStr,
                self._to_bytes(
                    cast(
                        str,
                        data_to_write,
                    )
                ),
            )

        stream.write(cast(AnyStr, data_to_write))


class _VersionSupportingEncoder(JSONEncoder):
    def default(self, o: Any) -> str:
        if isinstance(o, Version):
            return str(o)

        return super().default(o)
