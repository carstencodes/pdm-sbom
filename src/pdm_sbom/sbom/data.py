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
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Iterable

from packaging.version import Version


class ComponentUsage(IntEnum):
    Root = auto()
    Direct = auto()
    Optional = auto()
    Development = auto()


@dataclass
class PdmGraphPackage:
    package: str = field()
    version: str = field()
    required: str = field()
    dependencies: list["PdmGraphPackage"] = field(
        default_factory=list,
        hash=False,
    )


@dataclass(eq=True, frozen=True)
class Component:
    name: str = field()
    license_id: str = field()
    author: list[tuple[str, str]] = field(default_factory=list, hash=False)
    version: Version | None = field(default=None)
    dependencies: list["Component"] = field(
        default_factory=list, init=False, hash=False
    )

    def recurse(self) -> Iterable["Component"]:
        yield self
        for child in self.dependencies:
            yield from child.recurse()


@dataclass(eq=True, frozen=True)
class Project(Component):
    optional_dependencies: dict[str, list[Component]] = field(
        default_factory=dict,
        init=False,
        hash=False,
    )
    development_dependencies: dict[str, list[Component]] = field(
        default_factory=dict,
        init=False,
        hash=False,
    )

    def iterate(
        self, include_optional: bool = True, include_dev: bool = False
    ) -> Iterable[Component]:
        yield from self.dependencies
        if include_optional:
            for group in self.optional_dependencies.values():
                yield from group
        if include_dev:
            for group in self.development_dependencies.values():
                yield from group

    def recurse_project(
        self,
        include_optional: bool = True,
        include_dev: bool = False,
        include_self: bool = True,
    ) -> Iterable["UsedComponent"]:
        elements: set[UsedComponent] = set()
        if include_self:
            elements.add(UsedComponent(self, ComponentUsage.Root))
        for dependency in self.dependencies:
            for item in dependency.recurse():
                elements.add(UsedComponent(item, ComponentUsage.Direct))

        if include_optional:
            elements.update(self.__recurse_optionals())

        if include_dev:
            elements.update(self.__recurse_dev())

        return elements

    def __recurse_optionals(self) -> Iterable["UsedComponent"]:
        for group in self.optional_dependencies.values():
            for dependency in group:
                for item in dependency.recurse():
                    yield UsedComponent(
                        item,
                        ComponentUsage.Optional,
                    )

    def __recurse_dev(self) -> Iterable["UsedComponent"]:
        for dependency in self.development_dependencies:
            for item in dependency.recurse():
                yield UsedComponent(
                    item,
                    ComponentUsage.Development,
                )


@dataclass(eq=True, frozen=True)
class UsedComponent:
    component: Component = field(hash=True)
    usage: ComponentUsage = field(hash=False)
