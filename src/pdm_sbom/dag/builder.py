from collections.abc import Mapping
from typing import Optional

from pdm_sbom.dag.graph import Graph, Node, UsageKind, ComponentNode, RootNode
from pdm_sbom.project import ProjectInfo, ComponentInfo
from pdm_sbom.project.dataclasses import DependencyInfo


class GraphBuilder:
    def __init__(self, project: ProjectInfo) -> None:
        self.__project = project
        self.__graph = Graph(RootNode(project))

    def build(self) -> Graph:
        component_to_nodes: dict[ComponentInfo, Node] = {
            self.__project: self.__graph.root_node
        }

        self.__build_graph_nodes(self.__project, component_to_nodes)
        self.__colorize_graph(component_to_nodes)
        return self.__graph

    def __build_graph_nodes(self, component: ComponentInfo,
                            component_to_nodes: dict[ComponentInfo, Node],
                            group: Optional[str] = None) -> None:
        if component not in component_to_nodes:
            node = ComponentNode(component, group)
            component_to_nodes[component] = node
            self.__graph.add_node(node)

        for new_group, dependency in component.all_dependencies():
            self.__build_graph_nodes(dependency.component, component_to_nodes, new_group)
            self.__graph.add_edge(component_to_nodes[component], component_to_nodes[dependency.component])

    def __colorize_graph(self, component_to_nodes: Mapping[ComponentInfo, Node]) -> None:
        for development_dependency in self.__project.development_dependencies:
            GraphBuilder.__paint_all(development_dependency, component_to_nodes, UsageKind.DEVELOPMENT)
        for optional_dependency in self.__project.optional_dependencies:
            GraphBuilder.__paint_all(optional_dependency, component_to_nodes, UsageKind.OPTIONAL)

        for direct_dependency in self.__project.default_dependencies:
            GraphBuilder.__paint_all(direct_dependency, component_to_nodes, UsageKind.REQUIRED)

    @staticmethod
    def __paint_all(dependency: DependencyInfo, component_to_nodes: Mapping[ComponentInfo, Node], color: UsageKind) -> None:
        component: ComponentInfo = dependency.component
        if component in component_to_nodes:
            component_to_nodes[component].usage = color
            for _, transitive_dependency in component.all_dependencies():
                GraphBuilder.__paint_all(transitive_dependency, component_to_nodes, color)
