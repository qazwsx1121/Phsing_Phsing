import shutil

import pytest

from phishguard.config import load_resources, load_settings, resource_dir


def test_load_default_resources():
    r = load_resources()
    assert "bit.ly" in r.shorteners and "han.gl" in r.shorteners
    assert "xyz" in r.risky_tlds
    assert r.rule_thresholds == (30, 60)
    assert len(r.brands) == 30


def test_korean_brands_and_shorteners_present():
    r = load_resources()
    names = {b.name for b in r.brands}
    assert {"우체국", "CJ대한통운", "국민건강보험", "정부24", "네이버"} <= names
    assert {"me2.do", "vo.la", "url.kr", "naver.me"} <= r.shorteners


def test_brand_keywords_are_lowercase_ascii():
    for b in load_resources().brands:
        assert b.keywords and b.official_domains
        for k in b.keywords:
            assert k == k.lower() and k.isascii()


def test_rule_weights_cover_all_rule_ids():
    assert set(load_resources().rule_weights) == {f"R{i:02d}" for i in range(1, 19)}


def test_txt_loader_ignores_comments_and_blank(tmp_path):
    shutil.copytree(resource_dir(), tmp_path, dirs_exist_ok=True)
    (tmp_path / "shorteners.txt").write_text("# c\n\nBIT.LY\n", encoding="utf-8")
    assert load_resources(tmp_path).shorteners == frozenset({"bit.ly"})


def test_invalid_thresholds_raise(tmp_path):
    shutil.copytree(resource_dir(), tmp_path, dirs_exist_ok=True)
    weights = "\n".join(f"  R{i:02d}: 10" for i in range(1, 19))
    (tmp_path / "rules.yaml").write_text(
        f"weights:\n{weights}\nthresholds:\n  suspicious: 60\n  dangerous: 30\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        load_resources(tmp_path)


def test_settings_defaults(monkeypatch, tmp_path):
    for name in ("PHISHGUARD_CACHE_PATH", "PHISHGUARD_MODEL_PATH", "PHISHGUARD_PSL_REFRESH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    s = load_settings()
    assert s.cache_path == tmp_path / "cache.sqlite3"
    assert s.model_path == tmp_path / "models" / "model.joblib"
    assert s.psl_refresh is False
    assert s.http_timeout == 5.0 and s.lookup_timeout == 8.0


def test_settings_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISHGUARD_CACHE_PATH", str(tmp_path / "c.db"))
    monkeypatch.setenv("PHISHGUARD_MODEL_PATH", str(tmp_path / "m.joblib"))
    monkeypatch.setenv("PHISHGUARD_PSL_REFRESH", "1")
    s = load_settings()
    assert s.cache_path == tmp_path / "c.db"
    assert s.model_path == tmp_path / "m.joblib"
    assert s.psl_refresh is True
