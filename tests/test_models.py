import dataclasses
import json

import pytest

from phishguard.models import FEATURE_NAMES, FeatureVector, ModelResult, Verdict


def test_feature_names_are_unique_and_25():
    assert len(FEATURE_NAMES) == 25 and len(set(FEATURE_NAMES)) == 25


def test_feature_vector_orders_by_feature_names():
    values = {n: float(i) for i, n in enumerate(FEATURE_NAMES)}
    fv = FeatureVector(values=values, evidence={})
    assert fv.to_list() == [float(i) for i in range(25)]


def test_feature_vector_rejects_missing_key():
    with pytest.raises(ValueError):
        FeatureVector(values={n: 0.0 for n in FEATURE_NAMES[:-1]}, evidence={})


def test_verdict_most_severe():
    assert Verdict.most_severe(Verdict.SAFE, Verdict.DANGEROUS, Verdict.SUSPICIOUS) is Verdict.DANGEROUS


def test_final_verdict_without_model_is_rule_verdict(sample_result):
    assert sample_result.final_verdict is sample_result.rule.verdict


def test_final_verdict_with_model_is_most_severe(sample_result):
    r = dataclasses.replace(sample_result, model=ModelResult(0.9, Verdict.DANGEROUS, "v1"))
    assert r.final_verdict is Verdict.DANGEROUS


def test_to_dict_is_json_serializable_and_nan_is_none(sample_result):
    d = sample_result.to_dict()
    json.dumps(d, allow_nan=False)  # must not raise
    assert d["features"]["domain_age_days"] is None
    assert d["final_verdict"] == "suspicious"
    assert set(d["features"]) == set(FEATURE_NAMES)
    assert d["model"] is None
