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

    @app.get("/ui/favicon.ico", include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(str(root.joinpath("favicon.ico")))

    @app.get("/ui/favicon-16x16.png", include_in_schema=False)
    async def favicon_16() -> FileResponse:
        return FileResponse(str(root.joinpath("favicon-16x16.png")))

    @app.get("/ui/favicon-32x32.png", include_in_schema=False)
    async def favicon_32() -> FileResponse:
        return FileResponse(str(root.joinpath("favicon-32x32.png")))

    @app.get("/ui/apple-touch-icon.png", include_in_schema=False)
    async def apple_touch_icon() -> FileResponse:
        return FileResponse(str(root.joinpath("apple-touch-icon.png")))

    app.mount_static(directory=str(root.joinpath("assets")), path="/ui/assets")
