import hashlib
from abc import ABC, abstractmethod
from collections.abc import Sequence, Mapping, Iterator
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Final, Optional

from packageurl import PackageURL
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

DEFAULT_GROUP_NAME: Final[str] = "default"
DEVELOPMENT_GROUP_NAME: Final[str] = "development"
UNDEFINED_VERSION: Final[Version] = Version("0.0.0")


class AuthorInfo(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError()

    @property
    def description(self) -> Optional[str]:
        return None

    @property
    def email(self) -> Optional[str]:
        return None

    def __str__(self) -> str:
        return f"{self.name} {self.description if self.description is not None else ''} "\
               f"<{self.email if self.email is not None else ''}>"

    def __repr__(self) -> str:
        return (f"{type(self).__name__} name={self.name} "
                f"description={self.description if self.description is not None else 'None'}"
                f"email={self.email if self.email is not None else 'None'}")


@dataclass(frozen=True)
class ReferencedFile:
    file: str = field()
    hash: str = field()

    @cached_property
    def hash_algorithm(self) -> str:
        return self.hash.split(":", 2)[0]

    @cached_property
    def hash_value(self) -> str:
        return self.hash.split(":", 2)[1]

@dataclass(frozen=True)
class ReferencedComponent:
    name: str = field()
    version: str = field()
    required_python: str = field()
    summary: str = field()
    dependencies: Sequence[Requirement] = field(default_factory=list)
    extras: Sequence[str] = field(default_factory=list)
    files: Sequence[ReferencedFile] = field(default_factory=list)


@dataclass(frozen=True)
class LockFile:
    groups: Sequence[str] = field(default_factory=list)
    packages: Sequence[ReferencedComponent] = field(default_factory=list)


@dataclass(frozen=True)
class LicenseData:
    text: Optional[str] = field()
    file: Optional[Path] = field()


@dataclass(frozen=True)
class ProjectDefinition:
    name: str = field()
    version: Version = field()
    lockfile: LockFile = field()
    requires_python: SpecifierSet = field()
    license: LicenseData = field()
    homepage: Optional[str] = field()
    authors: Sequence[AuthorInfo] = field(default_factory=list)
    groups: Sequence[str] = field(default_factory=list)
    dependencies: Mapping[str, Sequence[Requirement]] = field(default_factory=dict)


@dataclass(frozen=True)
class LicenseInfo:
    pass


@dataclass(frozen=True)
class NoLicense(LicenseInfo):
    package_name: str = field()


@dataclass(frozen=True)
class DependencyInfo:
    requirement: Requirement = field()
    component: Optional["ComponentInfo"] = field()


@dataclass(frozen=True)
class ComponentInfo:
    name: str = field(hash=True)
    resolved_version: Version = field(hash=False)
    license: LicenseInfo = field(hash=False)
    authors: Sequence[AuthorInfo] = field(default_factory=list, hash=False)
    dependencies: dict[str, Sequence[DependencyInfo]] = field(default_factory=list, hash=False)
    files: Sequence[ReferencedFile] = field(default_factory=list, hash=False)
    resolved: bool = field(default=True, hash=True)
    homepage: Optional[str] = field(default=None, hash=False)

    def all_dependencies(self) -> Iterator[tuple[str, "DependencyInfo"]]:
        for group, dependencies in self.dependencies.items():
            for dependency in dependencies:
                yield group, dependency

    def get_package_url(self) -> PackageURL:
        return PackageURL(
            type="pypi",
            name=self.name,
            version=str(self.resolved_version) if self.resolved else None,
        )


@dataclass(frozen=True)
class ProjectInfo(ComponentInfo):
    groups: Sequence[str] = field(default_factory=list, hash=False)

    @property
    def default_dependencies(self) -> Sequence[DependencyInfo]:
        return self.dependencies.get(DEFAULT_GROUP_NAME, [])

    @property
    def development_dependencies(self) -> Sequence[DependencyInfo]:
        return self.dependencies.get(DEVELOPMENT_GROUP_NAME, [])

    @property
    def optional_dependencies(self) -> Sequence[DependencyInfo]:
        items = []
        for group in self.dependencies.keys():
            if group in (DEFAULT_GROUP_NAME, DEVELOPMENT_GROUP_NAME):
                continue
            items.extend(self.dependencies[group])

        return items

    def get_dependencies(self, group: str) -> Sequence[DependencyInfo]:
        return self.dependencies.get(group, [])


@dataclass(frozen=True)
class ToolInfo:
    name: str = field()
    version: Version = field()
    vendor: str = field()
