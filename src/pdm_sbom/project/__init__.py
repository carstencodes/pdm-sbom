from pathlib import Path

from .dataclasses import (
    AuthorInfo, LicenseInfo, ProjectInfo, ComponentInfo, ToolInfo,
    UNDEFINED_VERSION, ProjectDefinition as _ProjectDefinition
)
from ..core.abstractions import LockFileProvider

from .reader import ProjectReader as _ProjectReader
from .builder import ProjectBuilder as _ProjectBuilder
from .tools import create_pdm_info, create_self_info


def get_project_info(lf: LockFileProvider, dist_dir: str = "dist") -> ProjectInfo:
    dist: Path = lf.root / dist_dir
    project_bin_files: list[Path] = (list(dist.glob("**/*.whl")) + list(dist.glob("**/*.tar.gz"))
                                     if dist.is_dir() else [])
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
    create_pdm_info.__name__,
]
