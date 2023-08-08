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
from pathlib import Path
from typing import Any, Final, Protocol, TypeAlias, final

# MyPy does not recognize this during pull requests
from pdm.cli.commands.base import BaseCommand  # type: ignore
from pdm.core import Project  # type: ignore
from pdm.termui import UI  # type: ignore
from pdm.exceptions import PdmException  # type: ignore

from .sbom import (
    ExporterBase,
    SupportsFileFormat,
    SupportsFileVersion,
    ProjectBuilder,
    Project as SBomProject,
    ToolInfo,
    get_exporter,
)
from .sbom.tools import create_pdm_info, create_self_info


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
        try:
            builder: ProjectBuilder = ProjectBuilder(project)
            sbom: SBomProject = builder.build()

            exporter: ExporterBase = get_exporter(
                "spdx",
                sbom,
                create_self_info(),
                create_pdm_info(),
            )
            import sys
            exporter.export(sys.stdout)
        except PdmException as pde:
            raise SystemExit(2) from pde