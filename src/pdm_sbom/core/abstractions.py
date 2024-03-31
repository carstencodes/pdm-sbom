from typing import Protocol, Final

from pdm_pfsc.abstractions import ProjectLike


class LockFileProvider(ProjectLike, Protocol):
    LOCKFILE_FILENAME: Final[str] = "pdm.lock"
