from importlib.metadata import PackageMetadata, metadata

from packaging.version import Version

from pdm_sbom.project import ToolInfo, UNDEFINED_VERSION


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

    return ToolInfo(
        name, Version(version) if version != "" else UNDEFINED_VERSION, author)
