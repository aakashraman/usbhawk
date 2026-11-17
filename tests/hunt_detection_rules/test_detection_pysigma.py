"""Module #4: the generated Sigma pack is checked by pySigma, the reference Sigma implementation.

1. pySigma parses every rule and resolves the H3 correlation to its base rule.
2. All of pySigma's built-in validators pass.
3. SigmaHQ's own repository validators (pysigma-validators-sigmahq: title case, UUID v4, file-name prefixes,
   no MITRE links in references...) pass, so the rules meet the public SigmaHQ conventions.

Optional dependencies: pip install -e ".[sigma]" (tests skip when they are missing).
"""

import pytest

pytest.importorskip("sigma", reason="pySigma not installed: pip install -e .[sigma]")

from sigma.collection import SigmaCollection          # noqa: E402
from sigma.correlations import SigmaCorrelationRule   # noqa: E402
from sigma.validation import SigmaValidator           # noqa: E402

from usbhawk.detections import build, load_rules        # noqa: E402


@pytest.fixture(scope="module")
def pack(tmp_path_factory):
    root = tmp_path_factory.mktemp("sigma_pack")
    for rel, text in build(load_rules(), "sigma").items():
        if rel.endswith(".yml"):
            path = root / rel.split("/")[1]
            path.write_text(text, encoding="utf-8", newline="\n")
    return SigmaCollection.load_ruleset(sorted(root.glob("*.yml")))


def test_pysigma_parses_every_rule(pack):
    assert len(pack.rules) == 11
    assert [str(e) for r in pack.rules for e in r.errors] == []


def test_pysigma_resolves_the_correlation(pack):
    corr = [r for r in pack.rules if isinstance(r, SigmaCorrelationRule)]
    assert len(corr) == 1
    assert [ref.rule.title for ref in corr[0].rules] == ["Bulk File Copy to Removable Media - Single Event"]


def test_builtin_validators_pass(pack):
    from sigma.validators.core import validators
    issues = SigmaValidator(validators.values()).validate_rules(pack.rules)
    assert [f"{type(i).__name__}: {[r.title for r in i.rules]}" for i in issues] == []


def test_sigmahq_repository_validators_pass(pack):
    pytest.importorskip("sigma.validators.sigmahq", reason="pip install pysigma-validators-sigmahq")
    from sigma.plugins import InstalledSigmaPlugins
    validators = InstalledSigmaPlugins.autodiscover().validators
    assert any(k.startswith("sigmahq") for k in validators)
    issues = SigmaValidator(validators.values()).validate_rules(pack.rules)
    assert [f"{type(i).__name__}: {[r.title for r in i.rules]}" for i in issues] == []
