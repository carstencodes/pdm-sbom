from collections.abc import Mapping
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.version import Version
from pyproject_metadata import StandardMetadata
from pdm_pfsc.logging import logger, traced_function


from .dataclasses import LockFile, ReferencedComponent, ReferencedFile, ProjectDefinition, AuthorInfo, \
    DEFAULT_GROUP_NAME, DEVELOPMENT_GROUP_NAME, LicenseData, UNDEFINED_VERSION
from ..core.compat import load_toml

from ..core.abstractions import LockFileProvider


class AuthorSpec(AuthorInfo):
    def __init__(self, name: str, email: str) -> None:
        self.__name: str = name
        self.__email: str = email

    @property
    def name(self) -> str:
        return self.__name

    @property
    def email(self) -> str:
        return self.__email


class LockFileVersion(tuple[int, int, int]):
    @classmethod
    def parse(cls, value: str) -> "LockFileVersion":
        version = Version(value)

        values = (version.major, version.minor, version.micro)

        return cls(values)


class ProjectReader:
    def __init__(self, project: LockFileProvider) -> None:
        self.__lock_file: Path = project.root / project.LOCKFILE_FILENAME
        self.__project_file: Path = project.root / project.PYPROJECT_FILENAME
        self.__project_root: Path = project.root

    @traced_function
    def read(self) -> ProjectDefinition:
        logger.debug(f"Reading {self.__lock_file}")
        with self.__lock_file.open("rb") as file:
            lock_data: Mapping[str, Any] = load_toml(file)
            logger.debug("Controlling lock file version")
            lock_version: str = lock_data.get("metadata", {}).get("lock_version", "")
            logger.debug("Found lock version: %s", lock_version)
            lock_file_version = LockFileVersion.parse(lock_version)
            if lock_file_version < (4, 4, 1) or lock_file_version >= (5, 0, 0):
                logger.error("Lock file version is unsupported: %s", lock_version)
                raise ValueError("This lockfile reader only works for PDM Lock"
                                 " versions less than 5.0.0, but later than 4.4.1")

        logger.debug(f"Reading {self.__project_file}")
        with self.__project_file.open("rb") as file:
            definition_data: Mapping[str, Any] = load_toml(file)
            logger.debug("Parsing project file")
            project_data: StandardMetadata = StandardMetadata.from_pyproject(definition_data, self.__project_root)

        return self.parse(project_data, definition_data, lock_data)

    @traced_function
    def parse(self,
              project_data: StandardMetadata,
              project_definition_data: Mapping[str, Any],
              lock_data: Mapping[str, Any]) -> ProjectDefinition:
        lmd: dict[str, Any] = lock_data["metadata"]
        groups: list[str] = lmd["groups"]
        packages: list[dict[str, Any]] = lock_data["package"]

        logger.debug("Analyzing lock meta data %s", lmd)

        pkgs: list[ReferencedComponent] = []
        for pkg in packages:
            logger.debug("Analyzing package %s", pkg)
            files: list[dict[str, str]] = pkg["files"]
            fls: list[ReferencedFile] = []
            for f in files:
                file: ReferencedFile = ReferencedFile(
                    file=f["file"],
                    hash=f["hash"],
                )
                fls.append(file)

            comp: ReferencedComponent = ReferencedComponent(
                name=pkg["name"],
                version=pkg.get("version", str(UNDEFINED_VERSION)),
                files=fls,
                required_python=pkg.get("requires_python", ""),
                summary=pkg.get("summary", ""),
                extras=pkg.get("extras", []),
                dependencies=[Requirement(r) for r in pkg.get("dependencies", [])],
            )

            logger.debug("Resulting component is %s", comp)
            pkgs.append(comp)

        logger.debug("Setting up log-file with groups %s and %i packages", groups, len(pkgs))
        lf: LockFile = LockFile(groups=groups, packages=pkgs)

        authors: list[AuthorInfo] = []
        for author in project_data.authors:
            name, email = author
            author_instance = AuthorSpec(
                    name=name,
                    email=email,
                )

            logger.debug("Adding author %s", author_instance)

            authors.append(
                author_instance
            )

        groups: set[str] = set()
        dependencies: dict[str, list[Requirement]] = {DEFAULT_GROUP_NAME: list(project_data.dependencies)}

        for group, deps in project_data.optional_dependencies.items():
            groups.add(group)
            logger.debug("Adding dependency group %s with requirements %s", group, [d.name for d in deps])
            dependencies[group] = list(deps)

        for dg in project_definition_data.get("development-dependencies", {}):
            dev_dependencies = []
            for dg_name, deps in dg.items():
                logger.debug("Adding dev-dependency group %s with %s to overall dev-dependencies",
                             dg_name, [d.name for d in deps])
                dev_dependencies.extend(list(deps))

            dependencies[DEVELOPMENT_GROUP_NAME] = dev_dependencies

        pd: ProjectDefinition = ProjectDefinition(
            name=project_data.name,
            version=project_data.version or UNDEFINED_VERSION,
            license=LicenseData(
                text=project_data.license.text,
                file=project_data.license.file,
            ),
            groups=list(groups),
            dependencies=dependencies,
            authors=authors,
            requires_python=project_data.requires_python,
            lockfile=lf,
            homepage=project_data.urls.get("homepage", None)
        )

        logger.debug("Created project %s", pd)

        return pd
