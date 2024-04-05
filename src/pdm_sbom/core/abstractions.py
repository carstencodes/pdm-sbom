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
from typing import Protocol

from pdm_pfsc.abstractions import ProjectLike


class LockFileProvider(ProjectLike, Protocol):
    LOCKFILE_FILENAME: str = "pdm.lock"
