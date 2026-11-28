# Tenant certificate permissions

The certificate authorization regression used the installed Tigrbl application,
SQLite, standard API keys and a test ACME issuer. The owner completed renewal
and deletion. A different tenant with global metadata visibility could view the
metadata but received 404 for renewal, deletion and archive download. A
download-only key for the owner retrieved the ZIP archive and received 403 for
metadata. Keys with metadata read permission received 403 for downloads.

The four certificate and identity runtime modules passed 27 tests. The
application runtime, lifecycle and API security suites passed 18 more tests.
