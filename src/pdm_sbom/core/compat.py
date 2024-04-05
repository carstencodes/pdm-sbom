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
try:
    from tomllib import load as _load  # type: ignore
except ImportError:
    from tomli import load as _load  # type: ignore


load_toml = _load
