"""No-build operator UI mounting helpers."""

from importlib.resources import files

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles


def mount_uix(app: FastAPI) -> None:
    """Mount packaged static assets and a stable console entry point."""
    root = files("portwyrm.uix").joinpath("static")
    app.mount("/ui", StaticFiles(directory=str(root), html=True), name="ui")

    @app.get("/", include_in_schema=False)
    async def root_redirect() -> RedirectResponse:
        return RedirectResponse("/ui/")

    @app.get("/console", include_in_schema=False)
    async def console() -> FileResponse:
        return FileResponse(str(root.joinpath("index.html")))
