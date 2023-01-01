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
from importlib.metadata import PackageMetadata, metadata

from .base import ToolInfo


def create_self_info() -> ToolInfo:
    return create_module_info('pdm_sbom')


def create_pdm_info() -> ToolInfo:
    return create_module_info('pdm')


def create_module_info(module_name: str) -> ToolInfo:
    meta_data: PackageMetadata = metadata(module_name)
    name = meta_data['Name'] or "Undefined"
    version = meta_data['Version'] or ""

    author = meta_data['Author'] or ""
    author_email = meta_data['Author-email'] or ""

    author = "; ".join([f for f in (
        author,
        author_email,
        ) if f is not None and f != ""])

    return ToolInfo(author, name, version)
