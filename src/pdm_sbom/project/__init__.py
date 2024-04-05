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
from pathlib import Path

from ..core.abstractions import LockFileProvider
from .builder import ProjectBuilder as _ProjectBuilder
from .dataclasses import AuthorInfo, ComponentInfo, LicenseInfo
from .dataclasses import ProjectDefinition as _ProjectDefinition
from .dataclasses import ProjectInfo, ToolInfo
from .reader import ProjectReader as _ProjectReader
from .tools import create_pdm_info, create_self_info


def get_project_info(
    lf: LockFileProvider, dist_dir: str = "dist"
) -> ProjectInfo:
    dist: Path = lf.root / dist_dir
    project_bin_files: list[Path] = (
        list(dist.glob("**/*.whl")) + list(dist.glob("**/*.tar.gz"))
        if dist.is_dir()
        else []
    )
    project_reader: _ProjectReader = _ProjectReader(lf)
    definition: _ProjectDefinition = project_reader.read()
    project_builder: _ProjectBuilder = _ProjectBuilder(definition)
    project: ProjectInfo = project_builder.build(*tuple(project_bin_files))
    return project


__all__ = [
    get_project_info.__name__,
    AuthorInfo.__name__,
    LicenseInfo.__name__,
    ProjectInfo.__name__,
    ComponentInfo.__name__,
    ToolInfo.__name__,
    ToolInfo.__name__,
    create_pdm_info.__name__,
    create_self_info.__name__,
]
