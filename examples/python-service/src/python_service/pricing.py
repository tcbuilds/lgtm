"""Pricing helpers for the fixture service."""


def apply_discount(price_cents: int, percent_off: int) -> int:
    """Return the price in cents after applying a whole-percent discount.

    Args:
        price_cents: The pre-discount price in integer cents. Must be >= 0.
        percent_off: The discount as a whole percentage in the range 0..=100.

    Returns:
        The discounted price in integer cents, rounded down to the nearest cent.

    Raises:
        ValueError: If ``price_cents`` is negative or ``percent_off`` is outside
            the inclusive range 0 to 100.
    """
    if price_cents < 0:
        raise ValueError(f"price_cents must be non-negative, got {price_cents}")
    if not 0 <= percent_off <= 100:
        raise ValueError(f"percent_off must be within 0..=100, got {percent_off}")

    remaining = 100 - percent_off
    return price_cents * remaining // 100
