import pytest

from sentinel.redteam.stats import wilson


def test_zero_successes():
    low, high = wilson(0, 10)
    assert low == 0.0 and high == pytest.approx(0.278, abs=0.001)


def test_all_successes():
    low, high = wilson(10, 10)
    assert high == 1.0 and low == pytest.approx(0.722, abs=0.001)


def test_no_trials_is_vacuous_interval():
    assert wilson(0, 0) == (0.0, 1.0)


def test_interval_contains_point_estimate():
    low, high = wilson(3, 12)
    assert low < 0.25 < high
