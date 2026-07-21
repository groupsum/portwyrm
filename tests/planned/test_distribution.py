from pathlib import Path


def test_container_distribution_declares_runtime_and_health_contract() -> None:
    dockerfile = (Path(__file__).parents[2] / "Dockerfile").read_text(encoding="utf-8")
    assert "HEALTHCHECK" in dockerfile
    assert "EXPOSE 80 81 443" in dockerfile
    assert '"pip==26.1.2"' in dockerfile
    assert "PORTWYRM_AUTO_BOOTSTRAP_ADMIN=1" in dockerfile
    assert "PORTWYRM_BOOTSTRAP_CREDENTIAL_FILE=/data/bootstrap-admin.json" in dockerfile
    assert "PORTWYRM_INITIAL_ADMIN_PASSWORD=" not in dockerfile
    assert 'ENTRYPOINT ["python", "/app/deploy/entrypoint.py"]' in dockerfile
    assert 'org.opencontainers.image.source=' in dockerfile
    assert 'org.opencontainers.image.revision=' in dockerfile


def test_ui_favicons_are_included_in_package_data() -> None:
    pyproject = (Path(__file__).parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    for pattern in ('"static/*.png"', '"static/*.ico"'):
        assert pattern in pyproject


def test_container_publication_is_multiarch_attested_signed_and_verified() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "container.yml").read_text(
        encoding="utf-8"
    )

    assert "platforms: linux/amd64,linux/arm64" in workflow
    assert "provenance: mode=max" in workflow
    assert "sbom: true" in workflow
    assert "type=semver,pattern={{version}}" in workflow
    assert 'tags: ["v*"]' in workflow
    assert "type=raw,value=latest,enable=" in workflow
    assert "type=ref,event=branch" not in workflow
    assert "type=sha" not in workflow
    assert "needs: [databases, protocols, vulnerability-scan]" in workflow
    assert "cosign sign --yes" in workflow
    assert "uses: actions/attest@v4" in workflow
    assert "push-to-registry: true" in workflow
    assert "Verify GHCR package Actions access" in workflow
    assert "gh api /orgs/groupsum/packages/container/portwyrm" in workflow
    assert 'docker pull "$IMAGE"' in workflow
    assert 'cosign verify "$IMAGE"' in workflow
    assert 'gh attestation verify "oci://$IMAGE" --repo groupsum/portwyrm' in workflow


def test_container_vulnerability_scan_fails_closed_and_retains_evidence() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "container.yml").read_text(
        encoding="utf-8"
    )

    assert "severity: CRITICAL,HIGH" in workflow
    assert 'exit-code: "1"' in workflow
    assert "limit-severities-for-sarif: true" in workflow
    assert "output: trivy-results.sarif" in workflow
    assert "uses: actions/upload-artifact@v4" in workflow
    assert "uses: github/codeql-action/upload-sarif@v3" in workflow

def test_container_publication_has_only_protected_semver_channels() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "container.yml").read_text(
        encoding="utf-8"
    )

    assert 'tags: ["v*"]' in workflow
    assert "branches:" not in workflow
    assert "^v[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?$" in workflow
    assert "type=semver,pattern={{version}}" in workflow
    assert "type=semver,pattern={{major}}.{{minor}}" in workflow
    assert "type=semver,pattern={{major}}" in workflow
    assert "type=ref,event=branch" not in workflow
    assert "type=ref,event=tag" not in workflow
    assert "type=sha" not in workflow
    assert "value=latest,enable=" in workflow


def test_pull_requests_cannot_publish_or_sign() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "container.yml").read_text(
        encoding="utf-8"
    )

    assert "permissions:\n  contents: read" in workflow
    assert "push: " + "$" + "{{ github.event_name != 'pull_request' }}" in workflow
    assert "if: github.event_name != 'pull_request'\n        env:\n          DIGEST" in workflow
    assert "if: github.event_name != 'pull_request'\n        uses: actions/attest@v4" in workflow


def test_container_build_forwards_reproducible_oci_metadata() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "container.yml").read_text(
        encoding="utf-8"
    )
    dockerfile = (Path(__file__).parents[2] / "Dockerfile").read_text(encoding="utf-8")

    for argument in ("OCI_REVISION", "OCI_VERSION", "OCI_SOURCE", "OCI_CREATED"):
        assert argument in workflow
        assert argument in dockerfile