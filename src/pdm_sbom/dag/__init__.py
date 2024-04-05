#
# SPDX-License-Identifier: MIT
#
# Copyright (c) 2021-2024 Carsten Igel.
#
# This file is part of pdm-bump
# (see https://github.com/carstencodes/pdm-sbom).
#
# This file is published using the MIT license.
# Refer to LICENSE for more information
#
from ..project import ProjectInfo as _ProjectInfo
from .builder import GraphBuilder
from .graph import Graph, Node, UsageKind


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
