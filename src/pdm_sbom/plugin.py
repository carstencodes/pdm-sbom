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
from argparse import ArgumentParser, Namespace
_ConfigMapping: TypeAlias = dict[str, Any]


# Justification: Protocol for interoperability
class _CoreLike(Protocol):  # pylint: disable=R0903
    ui: UI


class _ProjectLike(Protocol):
    root: Path
    core: _CoreLike
    PYPROJECT_FILENAME: str

    @property
    def config(self) -> _ConfigMapping:
        # Method empty: Only a protocol stub
        pass


@final
class SBomCommand(BaseCommand):
    name: Final[str] = "sbom"
    description: str = "Generate a Software Bill of Materials according to your project"

    def add_arguments(self, parser: ArgumentParser) -> None:
        pass

    def handle(self, project: Project, options: Namespace) -> None:
        pass
