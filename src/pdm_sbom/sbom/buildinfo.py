import os
from collections.abc import Iterable, Sequence, Mapping
from datetime import datetime
from typing import IO, AnyStr, Optional

from buildinfo_om import BuildInfoBuilder, BuildAgentBuilder, AgentBuilder, ModuleBuilder, ArtifactBuilder, \
    DependencyBuilder, BuildInfo, save_to_buffer

from pdm_sbom.dag import Graph
from pdm_sbom.project import ComponentInfo, ProjectInfo, ToolInfo, create_pdm_info
from pdm_sbom.project.dataclasses import ReferencedFile
from pdm_sbom.sbom import ExporterBase


class _RecursiveDependencyListBuilder:
    def __init__(self, graph: Graph) -> None:
        self.__graph = graph

    def build(self) -> Mapping[ComponentInfo, Sequence[Sequence[ComponentInfo]]]:
        dependencies: dict[ComponentInfo, list[Sequence[ComponentInfo]]] = {n.component: [] for n in self.__graph.nodes}

        for node in self.__graph.nodes:
            component: ComponentInfo = node.component
            dependencies[component] = self.__get_graph_paths(component)

        return dependencies

    def __get_graph_paths(self, component: ComponentInfo) -> list[Sequence[ComponentInfo]]:
        item_paths: list[Sequence[ComponentInfo]] = []
        project: ProjectInfo = self.__graph.root_node.project
        for item_path in _RecursiveDependencyListBuilder.__walk_to(project, component, [project]):
            def _is_item_path(x: Sequence[ComponentInfo]) -> bool:
                return x == item_paths
            if item_path not in filter(_is_item_path, item_paths):
                item_paths.append(item_path)
        return item_paths

    @staticmethod
    def __walk_to(
            from_component: ComponentInfo,
            to_component: ComponentInfo,
            existing_paths: Iterable[ComponentInfo]) -> Iterable[Sequence[ComponentInfo]]:
        for _, dependency_list in from_component.dependencies.items():
            for dependency in dependency_list:
                paths = list(existing_paths)
                if to_component == dependency.component:
                    paths.reverse()
                    yield paths
                else:
                    paths.append(dependency.component)
                    yield from _RecursiveDependencyListBuilder.__walk_to(dependency.component, to_component, paths)


class BuildInfoExporter(ExporterBase):
    FORMAT_NAME: str = "buildinfo"
    FORMAT_DESCRIPTION = "JFrog Build Info file format. Can only be written as JSON file."
    SHORT_FORMAT_CODE: str = "bi"

    def __init__(self, graph: Graph, *tools: ToolInfo) -> None:
        ExporterBase.__init__(self, graph, *tools)

    @property
    def target_file_extension(self) -> str:
        return ".buildinfo.json"

    def export(self, stream: IO[AnyStr]) -> None:
        builder: BuildInfoBuilder = BuildInfoBuilder()
        builder.with_started(datetime.utcnow().isoformat())
        builder.collect_env()
        pdm_tool: ToolInfo = create_pdm_info()

        builder.with_build_agent(BuildAgentBuilder().with_name(pdm_tool.name).with_version(str(pdm_tool.version)))
        builder.with_agent(AgentBuilder().with_name("GENERIC"))
        # TODO builder.with_vcs()
        builder.with_version("1")
        builder.with_number(str(self.project.resolved_version))  # TODO
        builder.with_name(self.project.name)
        builder.with_type("ci" if os.getenv("CI") is not None else "personal")  # TODO
        # TODO builder.with_url()
        builder.with_modules(
            ModuleBuilder()
            .with_type("python")
            .with_id(self.project.get_package_url().to_string())
            .with_artifacts(
                *BuildInfoExporter._build_artifacts(self.project.files)
            )
            .with_dependencies(
                *tuple([d for d in self._build_dependencies()])
            )
        )

        build_info: BuildInfo = builder.build()
        save_to_buffer(build_info, stream)

    def _build_dependencies(self) -> Iterable[DependencyBuilder]:
        recursive_dependencies: Mapping[ComponentInfo, Sequence[Sequence[ComponentInfo]]]
        recursive_dependencies = _RecursiveDependencyListBuilder(self.graph).build()

        for group, dependency in self.project.all_dependencies():
            for file in dependency.component.files:
                file_type: str = "python"
                requesters = list(BuildInfoExporter._get_requesters_recursive(dependency.component,
                                                                              recursive_dependencies))

                if file_type is None:
                    if ".tar." in file.file:
                        index = file.file.rfind(".tar.")
                        file_ext = file.file[index:]
                        file_type = file_ext.lstrip(".")
                    elif "." in file.file:
                        index = file.file.rfind(".")
                        file_ext = file.file[index:]
                        file_type = file_ext.lstrip(".")
                builder = (DependencyBuilder()
                           .with_type(file_type)
                           .with_id(file.file)
                           .with_scopes(group)
                           .with_hash_value(file.hash_algorithm, file.hash_value))

                if len(requesters) > 0:
                    builder.with_requested_by(requesters)

                yield builder

    @staticmethod
    def _get_requesters_recursive(component: ComponentInfo,
                                  rd: Mapping[ComponentInfo, Sequence[Sequence[ComponentInfo]]]
                                  ) -> Iterable[Sequence[str]]:
        items: list[list[str]] = []

        if component in rd:
            recursive_dependencies = rd[component]
            if len(recursive_dependencies) > 0:
                for recursive_components in recursive_dependencies:
                    new_items: list[str] = []
                    for recursive_component in recursive_components:
                        new_items.extend([f.file for f in recursive_component.files])

                        items.append(new_items)

        items = BuildInfoExporter._distinct_items(items)
        for item in items:
            if len(item) > 0:
                yield item

    @staticmethod
    def _distinct_items(items: list[list[str]]) -> list[list[str]]:
        handled = []
        for item in items:
            def _is_handled(x: list[str]) -> bool:
                return x == item
            if item not in filter(_is_handled, handled):
                handled.append(item)

        return handled

    @staticmethod
    def _build_artifacts(files: Sequence[ReferencedFile]) -> tuple[ArtifactBuilder, ...]:
        artifact_builders: list[ArtifactBuilder] = [
            ArtifactBuilder()
            .with_type("python")
            .with_name(f.file)
            .with_hash_value(f.hash_algorithm, f.hash_value)

            for f in files
        ]

        return tuple(artifact_builders)
