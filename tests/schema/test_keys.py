from vmp.schema import keys


def test_host_key_marks_missing_port_and_protocol() -> None:
    assert keys.host_key("nessus", "73182", "10.0.0.5", None, None) == "nessus:73182:10.0.0.5:-:-"


def test_package_key_is_independent_of_cve_order() -> None:
    a = keys.package_key("trivy", ["CVE-2024-2", "CVE-2024-1"], "x", "pkg:npm/a@1")
    b = keys.package_key("trivy", ["CVE-2024-1", "CVE-2024-2"], "x", "pkg:npm/a@1")
    assert a == b == "trivy:CVE-2024-1,CVE-2024-2:pkg:npm/a@1"


def test_package_key_falls_back_to_native_id_without_cve() -> None:
    assert keys.package_key("snyk", [], "SNYK-JS-1", "pkg:npm/a@1") == "snyk:SNYK-JS-1:pkg:npm/a@1"


def test_endpoint_key_is_independent_of_parameter_order() -> None:
    url = "https://app.example/login"
    a = keys.endpoint_key("zap", "s1", url, "POST", ["password", "email"])
    b = keys.endpoint_key("zap", "s1", url, "POST", ["email", "password", "email"])
    assert a == b == "zap:s1:https://app.example/login:POST:email,password:-"


def test_endpoint_key_separates_different_weaknesses_on_one_endpoint() -> None:
    url = "https://app.example/main.js"
    xss = keys.endpoint_key("mirror", "s1", url, "GET", [], ["CWE-79"])
    secret = keys.endpoint_key("mirror", "s1", url, "GET", [], ["CWE-798"])
    assert xss != secret
    assert xss == "mirror:s1:https://app.example/main.js:GET:-:CWE-79"
