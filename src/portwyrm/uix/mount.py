"""No-build control-plane UI mounting helpers."""

from importlib.resources import files

from tigrbl import FileResponse, RedirectResponse, TigrblApp


def mount_uix(app: TigrblApp) -> None:
    """Mount packaged static assets and a stable console entry point."""
    root = files("portwyrm.uix").joinpath("static")

    @app.get("/", include_in_schema=False)
    async def root_redirect() -> RedirectResponse:
        return RedirectResponse("/ui/")

    @app.get("/ui/", include_in_schema=False)
    async def ui_index() -> FileResponse:
        return FileResponse(str(root.joinpath("index.html")))

    @app.get("/console", include_in_schema=False)
    async def console() -> FileResponse:
        return FileResponse(str(root.joinpath("index.html")))

    app.mount_static(directory=str(root.joinpath("assets")), path="/ui/assets")
