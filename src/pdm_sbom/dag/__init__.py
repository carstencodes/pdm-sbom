from .graph import Node, UsageKind, Graph
from .builder import GraphBuilder
from ..project import ProjectInfo as _ProjectInfo


def build_dag(project: _ProjectInfo) -> Graph:
    graph_builder: GraphBuilder = GraphBuilder(project)
    return graph_builder.build()


__all__ = [
    build_dag.__name__,
    Node.__name__,
    UsageKind.__name__,
    Graph.__name__,
    GraphBuilder.__name__,
]
