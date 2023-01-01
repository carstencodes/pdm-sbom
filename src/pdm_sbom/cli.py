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
from typing import Protocol, Type

# MyPy cannot resolve this during pull request
from pdm.project.config import ConfigItem as _ConfigItem  # type: ignore

from .plugin import SBomCommand as _Command


class _CoreLike(Protocol):
    def register_command(
        self, command: Type[_Command], name: str | None = None
    ) -> None:
        # Method empty: Only a protocol stub
        pass

    @staticmethod
    def add_config(name: str, config_item: _ConfigItem) -> None:
        # Method empty: Only a protocol stub
        pass


def register_plugin(core: _CoreLike) -> None:
    core.register_command(_Command)
