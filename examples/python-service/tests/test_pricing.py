"""Behavior tests for the fixture pricing helper."""

import pytest

from python_service.pricing import apply_discount


def test_apply_discount_reduces_price_by_percent() -> None:
    assert apply_discount(1000, 25) == 750


def test_apply_discount_zero_percent_is_identity() -> None:
    assert apply_discount(1000, 0) == 1000


def test_apply_discount_full_percent_is_free() -> None:
    assert apply_discount(1000, 100) == 0


def test_apply_discount_rounds_down_to_cent() -> None:
    assert apply_discount(999, 33) == 669


def test_apply_discount_rejects_negative_price() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        apply_discount(-1, 10)


def test_apply_discount_rejects_out_of_range_percent() -> None:
    with pytest.raises(ValueError, match="0..=100"):
        apply_discount(1000, 150)
