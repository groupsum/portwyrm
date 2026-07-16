from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from tests.support import TestClient


def test_npmctl_discovery_endpoint_is_live() -> None:
    app = create_app(settings=PortwyrmSettings(backend="memory"))
    response = TestClient(app).get("/api/")
    assert response.status_code == 200
    assert response.json()["version"]
