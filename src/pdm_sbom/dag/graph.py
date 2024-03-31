from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence, Mapping, Iterable
from typing import Optional

from pdm_sbom.project import ComponentInfo, ProjectInfo

from enum import IntEnum


class UsageKind(IntEnum):
    UNUSED = 0
    DEVELOPMENT = 1
    OPTIONAL = 2
    REQUIRED = 4
    ROOT = 8


class Node(ABC):
    @property
    @abstractmethod
    def component(self) -> ComponentInfo:
        raise NotImplementedError()

    @property
    @abstractmethod
    def usage(self) -> UsageKind:
        raise NotImplementedError()

    @usage.setter
    @abstractmethod
    def usage(self, paint: UsageKind) -> None:
        raise NotImplementedError()

    @property
    def group(self) -> Optional[str]:
        return None


class ComponentNode(Node):
    def __init__(self, component: ComponentInfo, group: Optional[str] = None) -> None:
        self.__component = component
        self.__paint = UsageKind.UNUSED
        self.__group = group

    @property
    def component(self) -> ComponentInfo:
        return self.__component

    @property
    def usage(self) -> UsageKind:
        return self.__paint

    @usage.setter
    def usage(self, usage: UsageKind) -> None:
        if self.__paint.value < usage.value:
            self.__paint = usage

    @property
    def group(self) -> Optional[str]:
        return self.__group

    def __repr__(self) -> str:
        return "<ComponentNode {} {}>".format(self.component, self.usage)

    def __str__(self) -> str:
        return "<{} dependency {}>".format(self.usage, self.component)


class RootNode(Node):
    def __init__(self, project: ProjectInfo) -> None:
        self.__project = project

    @property
    def component(self) -> ComponentInfo:
        return self.__project

    @property
    def project(self) -> ProjectInfo:
        return self.__project

    @property
    def usage(self) -> UsageKind:
        return UsageKind.ROOT

    @usage.setter
    def usage(self, _: UsageKind) -> None:
        return

    def __repr__(self) -> str:
        return "<RootNode {} {}>".format(self.component, self.usage)

    def __str__(self) -> str:
        return "<{} dependency {}>".format(self.usage, self.component)


class Graph:
    def __init__(self, root_node: RootNode) -> None:
        self.__nodes: list[Node] = [root_node]
        self.__edges: dict[Node, set[Node]] = {root_node: set()}
        self.__root_node: RootNode = root_node

    def add_node(self, node: Node) -> None:
        self.__nodes.append(node)

    def add_edge(self, from_node: Node, to_node: Node) -> None:
        if from_node not in self.__nodes:
            raise ValueError("Invalid node: {}".format(from_node))
        if to_node not in self.__nodes:
            raise ValueError("Invalid node: {}".format(to_node))

        if from_node not in self.__edges:
            self.__edges[from_node] = set()

        edges = self.__edges[from_node]
        edges.add(to_node)

    @property
    def root_node(self) -> RootNode:
        return self.__root_node

    @property
    def nodes(self) -> Sequence[Node]:
        return self.__nodes

    @property
    def edges(self) -> Mapping[Node, Iterable[Node]]:
        return self.__edges

    def __getitem__(self, item: Node) -> Iterable[Node]:
        return self.__edges.get(item, [])

    def __iter__(self) -> Iterator[tuple[Node, Node]]:
        for node in self.__nodes:
            if node in self.__edges:
                for target in self.__edges[node]:
                    yield node, target

    def __repr__(self) -> str:
        return "<Graph <Nodes {}> <Edges {}>>".format(self.__nodes, self.__edges)

    def __str__(self) -> str:
        max_node_len: int = max(map(lambda n: len(n.component.name), self.__nodes))
        lines: list[str] = []
        for node in self.__nodes:
            line = "{node:{width}} [{paint}] -> ".format(
                node=node.component.name, paint=node.usage.name, width=max_node_len)
            if node in self.__edges:
                for target in self.__edges[node]:
                    line += "{node:}[{paint}],".format(
                        node=target.component.name, paint=target.usage.name)

            line = line.rstrip(",")
            lines.append(line)

        return "\n".join(lines)
