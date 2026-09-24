# TEST ONLY fixtures

`test-only-cert.pem` / `test-only-key.pem` are a self-signed certificate
pair generated once with openssl for `tests/phantom_secrets.rs` and the
proxy termination unit test. SANs: `localhost`, `127.0.0.1`; 100-year
expiry. They secure nothing — the key is committed on purpose so tests
can stand up a TLS fixture on loopback. Never reference them from
non-test code.
