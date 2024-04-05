#
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2021-2024 Carsten Igel.
#
# This file is part of pdm-bump
# (see https://github.com/carstencodes/pdm-sbom).
#
# This file is published using the MIT license.
# Refer to LICENSE for more information
#
import os
import sys
from argparse import ArgumentParser, Namespace
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, AnyStr, Final, Protocol, TypeAlias, final

# MyPy does not recognize this during pull requests
from pdm.cli.commands.base import BaseCommand
from pdm.core import Project
from pdm.termui import UI
from pdm_pfsc.logging import setup_logger, update_logger_from_project_ui

from .dag import Graph, build_dag
from .project import (
    ProjectInfo,
    create_pdm_info,
    create_self_info,
    get_project_info,
)
from .sbom import (
    ExporterBase,
    SupportsFileFormat,
    SupportsFileVersion,
    get_exporter,
    get_exporters,
)

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


@contextmanager
def cwd(path: os.PathLike):
    old_cwd: str = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old_cwd)


def open_target_stream(target_file: str, dest_path: Path) -> IO[AnyStr]:
    if target_file == "-":
        return sys.stdout

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    target_file_path: Path = dest_path / target_file
    return target_file_path.open("w+")  # TODO open mode


@final
class SBomCommand(BaseCommand):
    name: Final[str] = "sbom"
    description: str = (
        "Generate a Software Bill of Materials according to your project"
    )

    def add_arguments(self, parser: ArgumentParser) -> None:
        exporters = get_exporters()
        parser.add_argument(
            "--format",
            "-f",
            dest="format",
            default="json",
            action="store",
            choices=[f.name for f in exporters],
            help="Select the sbom file format. Defaults"
                 " to json. Available formats are: "
            f"{', '.join([f'{f.name} ({f.description})' for f in exporters])}",
        )

        parser.add_argument(
            "--output",
            "-o",
            dest="output_file",
            action="store",
            help="Sets the target file to write the generated sbom to."
                 " Defaults to <project-name>.<extension>."
            "Use - for stdout.",
        )

        parser.add_argument(
            "--dest",
            "-d",
            dest="destination_folder",
            action="store",
            default="dist",
            help="Gets the directory, where the generated binaries "
                 "have been stored. Defaults to 'dist'.",
        )

        parser.add_argument(
            "--target-dir",
            "-t",
            dest="target_dir",
            action="store",
            default=".",
            help="Gets the directory, where the generated sbom files "
                 "shall be stored. Defaults to <project-dir>.",
        )

        for exporter in exporters:
            if len(exporter.formats) == 0 and len(exporter.versions) == 0:
                continue

            group = parser.add_argument_group(
                f"{exporter.name.upper()} options",
                "Options for exporting "
                f"{exporter.name} sbom documents.",
            )
            if len(exporter.formats):
                group.add_argument(
                    f"--{exporter.name}-format",
                    f"-{exporter.short_format_code}f",
                    dest=f"{exporter.name}_file_format",
                    default=exporter.default_format,
                    action="store",
                    choices=list(exporter.formats),
                    help="Select the file output format to set "
                         f"for exported {exporter.name} file. "
                    f"Defaults to {exporter.default_format}.",
                )
            if len(exporter.versions):
                group.add_argument(
                    f"--{exporter.name}-version",
                    f"-{exporter.short_format_code}v",
                    dest=f"{exporter.name}_file_version",
                    default=exporter.default_version,
                    action="store",
                    choices=list(exporter.versions),
                    help="Select the file version to set for "
                         f"exported {exporter.name} file. "
                    f"Defaults to version {exporter.default_version}.",
                )

    def handle(self, project: Project, options: Namespace) -> None:
        if hasattr(options, "verbose"):
            setup_logger(options.verbose)

        update_logger_from_project_ui(project.core.ui)

        with cwd(project.root):
            project_info: ProjectInfo = get_project_info(
                project, options.destination_folder
            )
        graph: Graph = build_dag(project_info)
        exporter: ExporterBase = get_exporter(
            options.format,
            graph,
            create_self_info(),
            create_pdm_info(),
        )

        if isinstance(exporter, SupportsFileFormat) and hasattr(
            options, f"{options.format}_file_format"
        ):
            exporter.file_format = getattr(
                options, f"{options.format}_file_format"
            )

        if isinstance(exporter, SupportsFileVersion) and hasattr(
            options, f"{options.format}_file_version"
        ):
            exporter.file_version = getattr(
                options, f"{options.format}_file_version"
            )

        if not hasattr(options, "output_file") or options.output_file is None:
            options.output_file = (
                f"{project_info.name}{exporter.target_file_extension}"
            )

        if options.output_file != "-" and not options.output_file.endswith(
            exporter.target_file_extension
        ):
            options.output_file += exporter.target_file_extension

        with cwd(project.root):
            with open_target_stream(
                options.output_file, Path(options.target_dir).resolve()
            ) as buffer:
                exporter.export(buffer)
