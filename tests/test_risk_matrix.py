from vapt_framework.analytics.risk_matrix import RiskMatrixEngine, EMPIRICAL_RISK_DATA, RISK_VULN_COLUMNS

def test_risk_matrix_structure():
    engine = RiskMatrixEngine()
    assert len(engine.columns) == 10
    assert len(engine.data) == 12

    # Check key targets
    assert "blockchain.com" in engine.data
    assert "binance.com" in engine.data
    assert "crypto.com" in engine.data
    assert "m.kucoin.com" in engine.data

    # Check ratings for binance.com
    assert engine.data["binance.com"]["CSP Wildcard Directive"] == "M"
    assert engine.data["binance.com"]["CSP: script-src unsafe inline"] == "M"
    assert engine.data["binance.com"]["Cookie without same site attribute"] == "L"

def test_risk_matrix_formats():
    engine = RiskMatrixEngine()
    md = engine.to_markdown()
    csv_out = engine.to_csv()
    json_out = engine.to_json()

    assert "| Target Website |" in md
    assert "blockchain.com" in md
    assert "Target Website," in csv_out
    assert '"binance.com": {' in json_out
