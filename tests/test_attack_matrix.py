from vapt_framework.analytics.attack_matrix import AttackMatrixEngine, EMPIRICAL_ATTACK_MAPPINGS

def test_attack_matrix_mappings():
    engine = AttackMatrixEngine()
    assert len(engine.columns) == 10
    assert len(engine.mappings) == 10

    # Verify XSS mappings
    xss_vulns = engine.mappings["XSS attack"]
    assert "CSP Wildcard Directive" in xss_vulns
    assert "CSP: style-src unsafe inline" in xss_vulns
    assert "CSP: script-src unsafe inline" in xss_vulns
    assert "X-content type option header missing" in xss_vulns

    # Verify CSRF mappings
    csrf_vulns = engine.mappings["CSRF Attack"]
    assert "Absence of Anti-CSRF Tokens" in csrf_vulns
    assert "Cookie without same site attribute" in csrf_vulns

def test_attack_matrix_exports():
    engine = AttackMatrixEngine()
    md = engine.to_markdown()
    csv_out = engine.to_csv()
    json_out = engine.to_json()

    assert "| Attack Vector |" in md
    assert "XSS attack" in md
    assert "CSRF Attack" in md
    assert "Attack Vector," in csv_out
    assert '"CSRF Attack": {' in json_out
