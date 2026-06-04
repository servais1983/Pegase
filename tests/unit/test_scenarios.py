"""ThreatSim scenario engine tests."""

from __future__ import annotations

import pytest

from pegase.core.scenarios import list_builtin_scenarios, load_scenario


def test_builtin_scenarios_exist():
    builtins = list_builtin_scenarios()
    assert "external-apt" in builtins
    assert "recon-and-enumerate" in builtins


def test_load_builtin_scenario_resolves_modules():
    scen = load_scenario("external-apt")
    assert scen.validate() == []
    mods = scen.all_modules()
    assert mods[0] == "recon"
    assert "postxploit" in mods
    # parameters merged across stages
    params = scen.merged_parameters()
    assert params["netassault"]["ports"] == "1-1024"


def test_unknown_scenario_raises():
    with pytest.raises(ValueError, match="unknown scenario"):
        load_scenario("does-not-exist")


def test_load_scenario_from_yaml(tmp_path):
    yaml_text = """
name: custom
description: custom chain
stages:
  - name: recon
    modules: [recon]
  - name: web
    modules: [webbreacher]
    parameters:
      webbreacher:
        timeout: 5
"""
    p = tmp_path / "scen.yaml"
    p.write_text(yaml_text, encoding="utf-8")
    scen = load_scenario(str(p))
    assert scen.validate() == []
    assert scen.all_modules() == ["recon", "webbreacher"]
    assert scen.merged_parameters()["webbreacher"]["timeout"] == 5
