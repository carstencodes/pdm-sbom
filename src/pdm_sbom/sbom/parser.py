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
from collections.abc import MappingView
from importlib.metadata import PackageMetadata, Distribution, metadata
from io import StringIO
from json import loads as load_json
from pathlib import Path
from re import compile as compile_pattern
from sys import path as python_path
from sys import version_info
from types import SimpleNamespace
from typing import Any, cast

from packaging.version import Version
from pdm.cli.commands.list import Command as ListCommand  # type: ignore
from pdm.cli.commands.venv.utils import iter_venvs  # type: ignore
from pdm.core import Project as PdmProject  # type: ignore
from pdm.termui import Verbosity  # type: ignore
from pyproject_metadata import StandardMetadata  # type: ignore

from ._compat import load_toml
from .data import Component, PdmGraphPackage, Project


def _parse_meta_data(pyproject: Path) -> StandardMetadata:
    data: dict[str, Any]
    with pyproject.open("rb") as file_ptr:
        data = load_toml(file_ptr)

    return StandardMetadata.from_pyproject(data, pyproject.parent)


class ProjectBuilder:
    def __init__(self, project: PdmProject) -> None:
        self.__project = project
        self.__metadata = _parse_meta_data(
            self.__project.root / self.__project.PYPROJECT_FILENAME
        )

    def build(self) -> Project:
        list_options: SimpleNamespace = SimpleNamespace(
            freeze=False,
            graph=True,
            reverse=False,
            resolve=False,
            sort=False,
            csv=False,
            json=True,
            markdown=False,
            include="",
            exclude="",
            fields=ListCommand.DEFAULT_FIELDS,
        )

        old_echo = self.__project.core.ui.echo

        graph_buffer: StringIO = StringIO()

        def buffered_echo(
            message: str = "",
            err: bool = False,  # pylint: disable=W0613
            verbosity: Verbosity = Verbosity.NORMAL,  # pylint: disable=W0613
            **kwargs,  # pylint: disable=W0613
        ) -> None:
            _ = graph_buffer.write(message)

        pdm_ui = self.__project.core.ui

        try:
            setattr(pdm_ui, pdm_ui.echo.__name__, buffered_echo)
            sub_command: ListCommand = ListCommand(ArgumentParser())
            options: Namespace = cast(Namespace, list_options)
            sub_command.handle(self.__project, options)
        finally:
            setattr(pdm_ui, pdm_ui.echo.__name__, old_echo)

        json_graph = graph_buffer.getvalue()

        graph: list[dict[str, Any]] = load_json(json_graph)
        parsed: dict[str, PdmGraphPackage] = {}
        _ = ProjectBuilder.__parse_packages(graph, parsed)

        dependencies: list[Component] = []
        development_dependencies: dict[str, list[Component]] = {}
        optional_dependencies: dict[str, list[Component]] = {}
        ws: MappingView[str, Distribution] = self.__project.environment.get_working_set()
        parsed_components: dict[str, Component] = {}

        for dependency_name in self.__project.get_dependencies("default"):
            package: PdmGraphPackage = parsed[dependency_name]
            component = ProjectBuilder.__convert_package(
                package,
                parsed_components,
                ws,
            )
            dependencies.append(component)

        dev_dependency_groups = tuple(self.__project.pyproject.settings.get("dev-dependencies", {}))

        for group in self.__project.iter_groups():
            if group in dev_dependency_groups:
                continue

            optional_dependencies[group] = []
            for dependency_name in self.__project.get_dependencies(group):
                opt_package: PdmGraphPackage = parsed[dependency_name]
                component = ProjectBuilder.__convert_package(
                    opt_package,
                    parsed_components,
                    ws,
                )
                optional_dependencies[group].append(component)
        
        for group in dev_dependency_groups:
            development_dependencies[group] = []
            for dependency_name in self.__project.get_dependencies(group):
                dev_package: PdmGraphPackage = parsed[dependency_name]
                component = ProjectBuilder.__convert_package(
                    dev_package,
                    parsed_components,
                    ws,
                )
                development_dependencies[group].append(component)

        result: Project = Project(
            self.__metadata.name,
            self.__metadata.license.text
            if self.__metadata.license is not None
            else "[UNDEFINED]",
            self.__metadata.authors,
            self.__metadata.version,
        )
        
        result.dependencies.extend(dependencies)
        result.optional_dependencies.update(optional_dependencies)
        result.development_dependencies.update(development_dependencies)

        return result

    @staticmethod
    def __convert_packages(
        pdm_packages: list[PdmGraphPackage],
        components: dict[str, Component],
        ws: MappingView[str, Distribution],
    ) -> list[Component]:
        result: list[Component] = []

        for package in pdm_packages:
            component: Component
            if package.package in components:
                component = components[package.package]
                result.append(component)
                continue

            component = ProjectBuilder.__convert_package(
                package,
                components,
                ws,
            )
            components[package.package] = component
            result.append(component)

        return result

    @staticmethod
    def __get_author(
        name: str | None,
        email: str | None,
    ) -> list[tuple[str, str]]:
        if name is None and email is None:
            return []

        author_name = name or ""
        author_email = email or ""

        authors = f"{author_name} {author_email}".strip()

        result: list[tuple[str, str]] = []
        for author in authors.split(","):
            parser = Rfc822FromParser(author)
            if parser.name is None and parser.email is None:
                continue

            result.append((parser.name or "", parser.email or ""))

        return result

    @staticmethod
    def __convert_package(
        package: PdmGraphPackage,
        components: dict[str, Component],
        ws:  MappingView[str, Distribution]
    ) -> Component:
        name: str = package.package
        normalized_name = name.split("[")[0]
        if normalized_name in components:
            return components[normalized_name]

        dist: Distribution = ws[normalized_name]
        version: Version = Version(package.version)

        meta_data: PackageMetadata = dist.metadata
        author: str | None = meta_data["Author"]
        author_email: str | None = meta_data["Author-email"]
        license_field: str = meta_data["License"]

        dependencies: list[Component] = ProjectBuilder.__convert_packages(
            package.dependencies,
            components,
            ws,
        )

        authors = ProjectBuilder.__get_author(author, author_email)

        result: Component = Component(
            normalized_name,
            license_field,
            authors,
            version,
        )

        result.dependencies.extend(dependencies)

        components[normalized_name] = result

        return result

    @staticmethod
    def __parse_packages(
        package_graph: list[dict[str, Any]],
        parsed_packages: dict[str, PdmGraphPackage],
    ) -> list[PdmGraphPackage]:
        result: list[PdmGraphPackage] = []
        for package in package_graph:
            pkg: dict[str, Any] = package.copy()
            name: str = pkg.pop("package")
            if name in parsed_packages:
                result.append(parsed_packages[name])
                continue

            version: str = pkg.pop("version")
            required: str = pkg.pop("required")
            unparsed: list[dict[str, Any]] = pkg.pop("dependencies")
            dependencies = ProjectBuilder.__parse_packages(
                unparsed,
                parsed_packages,
            )

            new_item: PdmGraphPackage = PdmGraphPackage(
                name, version, required, dependencies
            )
            parsed_packages[name] = new_item
            result.append(new_item)

        return result


class _LoadContext:
    def __init__(self, project: PdmProject) -> None:
        self.__project = project
        self.__extended_path: list[str] = []

    def __enter__(self) -> "_LoadContext":
        if self.__project.environment.is_global:
            for _, venv in iter_venvs(self.__project):
                venv_site_packages: Path = (
                    venv
                    / "lib"
                    / f"python{version_info.major}.{version_info.minor}"
                    / "site-packages"
                )
                if venv_site_packages.exists():
                    self.__extended_path.append(str(venv_site_packages))
        else:
            py_packages: str = str(self.__project.environment.packages_path)
            self.__extended_path.append(py_packages)

        for pth in reversed(self.__extended_path):
            python_path.insert(0, pth)

        return self

    def __exit__(self, err, __, ___) -> bool:
        for value in self.__extended_path:
            python_path.remove(value)
        return err is None


class Rfc822FromParser:
    def __init__(self, text: str) -> None:
        self.__name = None
        self.__email = None
        pattern = compile_pattern(
            r"^\"?(?P<NAME>([a-zA-Z0-9\s\.]+))\"?\s+\<?(?P<MAIL>(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,})))\>?$"  # noqa: C0301, E501, S5843
        )
        result = pattern.match(text)
        if result is not None:
            self.__name = None
            if result.group("NAME") not in (None, ""):
                self.__name = result.group("NAME")
            self.__email = None
            if result.group("MAIL") not in (None, ""):
                self.__email = result.group("MAIL")

    @property
    def name(self) -> str | None:
        return self.__name

    @property
    def email(self) -> str | None:
        return self.__email
