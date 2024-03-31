import hashlib
import re
from collections.abc import Mapping, Sequence
from functools import cached_property
from importlib.metadata import PackageMetadata, metadata as resolve_metadata, PackageNotFoundError
from pathlib import Path
from typing import Callable, Optional, Final, ClassVar, Union

from packaging.requirements import Requirement
from packaging.version import VERSION_PATTERN as _UNNAMED_VERSION_PATTERN, Version
from pdm_pfsc.logging import traced_function, logger

from pdm_sbom.project.dataclasses import ProjectDefinition, ProjectInfo, ComponentInfo, ReferencedComponent, LockFile, \
    DependencyInfo, DEFAULT_GROUP_NAME, AuthorInfo, LicenseInfo, LicenseData, UNDEFINED_VERSION, \
    ReferencedFile, NoLicense

_REPLACE = re.compile(r"\?P<\w+>")
VERSION_PATTERN: Final[str] = _REPLACE.sub("", _UNNAMED_VERSION_PATTERN)


def unresolved_component(name: str, files: Sequence[ReferencedFile]) -> ComponentInfo:
    return ComponentInfo(
        name=name,
        files=files,
        resolved_version=UNDEFINED_VERSION,
        authors=[],
        license=LicenseInfo(),  # TODO
        dependencies={},
        resolved=False,
    )


class DependencyTreeError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class AuthorByDescription(AuthorInfo):
    def __init__(self, name: str) -> None:
        self.__name_data = name

    @cached_property
    def name(self) -> str:
        return self.__name_data  # TODO

    @cached_property
    def description(self) -> Optional[str]:
        return None  # TODO


class AuthorByEmail(AuthorInfo):
    def __init__(self, name: str) -> None:
        self.__name_data = name

    @cached_property
    def name(self) -> str:
        return self.__name_data  # TODO

    @cached_property
    def email(self) -> Optional[str]:
        return None  # TODO


class AuthorResolver:
    resolve_by_name: bool = True
    resolve_by_mail: bool = True

    def resolve(self, meta_data: PackageMetadata) -> Sequence[AuthorInfo]:
        authors: list[AuthorInfo] = []
        if self.resolve_by_name:
            for field in meta_data.get_all("Author", []):
                authors.append(AuthorByDescription(field))

        if self.resolve_by_mail:
            for field in meta_data.get_all("Author-email", []):
                authors.append(AuthorByEmail(field))

        return authors


class LicenseResolver:
    def resolve(self, meta_data: PackageMetadata) -> LicenseInfo:
        classifiers: list[str] = meta_data.get_all("Classifier", [])
        result: Optional[LicenseInfo] = self._resolve_from_classifiers(classifiers)
        if result is not None:
            return result

        return self._resolve_from_license(meta_data.get("License", None), meta_data["Name"])


    def _resolve_from_classifiers(self, classifiers: Sequence[str]) -> Optional[LicenseInfo]:
        return None  # TODO

    def _resolve_from_license(self, license_id: Optional[str], package_name: str) -> LicenseInfo:
        if license_id is None:
            return NoLicense(package_name=package_name)

        return LicenseInfo()  # TODO

    def resolve_from_license_data(self, license: LicenseData) -> LicenseInfo:
        return LicenseInfo()  # TODO


class UnresolvedPackage:
    def __init__(self, package_name: str) -> None:
        self.__package_name = package_name

    @property
    def package_name(self) -> str:
        return self.__package_name


class MetaDataResolver:
    resolver_method: ClassVar[Callable[[str], PackageMetadata]] = resolve_metadata

    def resolve(self, package_name: str) -> Union[PackageMetadata, UnresolvedPackage]:
        try:
            return resolve_metadata(package_name)
        except ValueError as ve:
            raise DependencyTreeError(f"Invalid package name: {package_name}") from ve
        except PackageNotFoundError:
            return UnresolvedPackage(package_name)


class ComponentBuilder:
    def __init__(self) -> None:
        self._components: dict[str, ComponentInfo] = {}
        self._author_resolver: AuthorResolver = AuthorResolver()
        self._license_resolver: LicenseResolver = LicenseResolver()
        self._meta_data_resolver: MetaDataResolver = MetaDataResolver()

    @traced_function
    def add_from_lock_file(self, lock_file: LockFile) -> None:
        package_map: Mapping[str, ReferencedComponent] = {m.name: m for m in lock_file.packages}
        for reference in package_map.values():
            logger.debug("Resolving reference for %s", reference.name)
            if reference.name not in self._components:
                logger.debug("Starting resolution for %s", reference.name)
                self._components[reference.name] = self._resolve(reference, package_map)

    @traced_function
    def _resolve(self, reference: ReferencedComponent, package_map: Mapping[str, ReferencedComponent]) -> ComponentInfo:
        if reference.name in self._components:
            logger.debug("Referenced %s already resolved", reference.name)
            return self._components[reference.name]

        dependencies: list[DependencyInfo] = []
        for dependency in reference.dependencies:
            if dependency.name == reference.name:
                if len(reference.dependencies) == 0:
                    logger.warning("Circular dependency detected. Ignoring %s", dependency.name)
                continue
            package_name: str = dependency.name
            if package_name not in package_map:
                raise DependencyTreeError(f"Could not find package {package_name} derived "
                                          f"from {dependency.name} in package map.")

            package = package_map[package_name]
            logger.debug("Resolving dependency %s for reference %s", dependency.name, reference.name)
            component: ComponentInfo = self._resolve(package, package_map)

            package_dependency: DependencyInfo = DependencyInfo(
                requirement=dependency,
                component=component
            )
            logger.debug("Resolved dependency %s for reference %s to %s",
                         dependency.name, reference.name, package_dependency)
            dependencies.append(package_dependency)

        resolved_dependencies = {DEFAULT_GROUP_NAME: dependencies}

        logger.debug("Resolving meta data for %s", reference.name)
        package_meta_data: Union[PackageMetadata, UnresolvedPackage] = self._meta_data_resolver.resolve(reference.name)

        result: ComponentInfo
        if not isinstance(package_meta_data, UnresolvedPackage):
            result = ComponentInfo(
                name=reference.name,
                dependencies=resolved_dependencies,
                authors=self._author_resolver.resolve(package_meta_data),
                files=reference.files,
                resolved_version=Version(reference.version),
                license=self._license_resolver.resolve(package_meta_data),
            )
        else:
            result = unresolved_component(
                name=reference.name,
                files=reference.files,
            )
            logger.warning("Failed to resolve package %s, as it is not installed. "
                           "Maybe due to falsified conditions.",
                           reference.name)

        logger.debug("Reference %s resolved to %s", reference.name, result)
        self._components[reference.name] = result

        return result

    @traced_function
    def resolve(self, requirement: Requirement) -> DependencyInfo:
        if requirement.name not in self._components:
            raise DependencyTreeError(f"Could not find dependency {requirement.name} in list of dependencies")

        component: ComponentInfo = self._components[requirement.name]
        parsed_dependency: DependencyInfo = DependencyInfo(requirement=requirement, component=component)

        return parsed_dependency


class ProjectBuilder:
    def __init__(self, project: ProjectDefinition) -> None:
        self.__project = project
        self.__license_resolver = LicenseResolver()

    @traced_function
    def build(self, *files: Path) -> ProjectInfo:
        def hash_file(path: Path) -> str:
            algo_name: str = "sha256"
            with path.open("rb") as buffer:
                digest = hashlib.file_digest(buffer, algo_name)  # type: ignore

            return f"{algo_name}:{digest.hexdigest()}"

        components: ComponentBuilder = ComponentBuilder()
        logger.debug("Creating component tree")
        components.add_from_lock_file(self.__project.lockfile)

        dependencies: dict[str, Sequence[DependencyInfo]] = {}
        group: str
        deps: Sequence[Requirement]
        for group, deps in self.__project.dependencies.items():
            logger.debug("Resolving dependencies for group %s", group)
            dependency_group: list[DependencyInfo] = []
            for dependency in deps:
                logger.debug("Resolving dependency %s", dependency.name)
                dependency_group.append(components.resolve(dependency))
            dependencies[group] = dependency_group

        pi: ProjectInfo = ProjectInfo(
            name=self.__project.name,
            license=self.__license_resolver.resolve_from_license_data(self.__project.license),
            authors=self.__project.authors,
            groups=self.__project.lockfile.groups,
            dependencies=dependencies,
            resolved_version=self.__project.version,
            files=[
                ReferencedFile(
                    file=f.name,
                    hash=hash_file(f)
                )
                for f in files if f.is_file()
            ],
            homepage=self.__project.homepage,
        )

        logger.debug("Created project %s", pi)

        return pi
