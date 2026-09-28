import pytest

from reconlens.cli import _grade_rank, _validate_grade
from reconlens.errors import InvalidTargetError


def test_grade_rank_order():
    assert _grade_rank("A") < _grade_rank("B") < _grade_rank("F")


def test_validate_grade_normalises():
    assert _validate_grade("b") == "B"
    assert _validate_grade(None) is None


def test_validate_grade_rejects_bad():
    with pytest.raises(InvalidTargetError):
        _validate_grade("Z")


def test_fail_under_logic():
    # Grade worse than threshold => should fail (rank greater).
    assert _grade_rank("D") > _grade_rank("A")  # D fails an "A" gate
    assert _grade_rank("A") <= _grade_rank("A")  # A passes an "A" gate
