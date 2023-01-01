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
from typing import AnyStr, IO, cast


class ReEncoder:
    def __init__(
        self,
        stream: IO[AnyStr],
    ) -> None:
        self.__stream: IO[AnyStr] = cast(IO[AnyStr], stream)  # type: ignore

    def __enter__(self) -> "ReEncoder":
        return self

    def __exit__(self, err, _, __) -> bool:
        return err is None

    @property
    def mode(self) -> str:
        return self.__stream.mode

    @property
    def name(self) -> str:
        return self.__stream.name

    def close(self) -> None:
        self.__stream.close()

    @property
    def closed(self) -> bool:
        return self.__stream.closed

    def fileno(self) -> int:
        return self.__stream.fileno()

    def flush(self) -> None:
        self.__stream.flush()

    def isatty(self) -> bool:
        return self.__stream.isatty()

    def read(self, n: int = -1) -> AnyStr:
        return self.__stream.read(n)  # type: ignore

    def readable(self) -> bool:
        return self.__stream.readable()

    def readline(self, limit: int = -1) -> AnyStr:
        return self.__stream.readline(limit)  # type: ignore

    def readlines(self, hint: int = -1) -> list[AnyStr]:
        return self.__stream.readlines(hint)  # type: ignore

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.__stream.seek(offset, whence)

    def seekable(self) -> bool:
        return self.__stream.seekable()

    def tell(self) -> int:
        return self.__stream.tell()

    def truncate(self, size: int | None = None) -> int:
        return self.__stream.truncate(size)

    def writable(self) -> bool:
        return self.__stream.writable()

    def write(self, s: AnyStr) -> int:
        if isinstance(s, bytes):
            if "b" in self.mode:
                return self.__stream.write(s)  # type: ignore
            else:
                return self.__stream.write(s.decode("utf-8"))  # type: ignore
        elif isinstance(s, str):
            if "b" not in self.mode:
                return self.__stream.write(s)  # type: ignore
            else:
                return self.__stream.write(s.encode("utf-8"))  # type: ignore
        else:
            raise ValueError(s)

    def writelines(self, lines: list[AnyStr]) -> None:
        for line in lines:
            self.write(line)
