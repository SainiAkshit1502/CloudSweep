"""Approximate AWS list prices used for savings estimates.

These are not a bill. Regional differences are not modelled.
EBS: https://aws.amazon.com/ebs/pricing/
Public IPv4 / Elastic IP: https://aws.amazon.com/vpc/pricing/
"""

HOURS_PER_MONTH = 730
EIP_HOURLY_USD = 0.005  # public IPv4 address, in-use or idle

EBS_GB_MONTH_USD = {
    "gp3": 0.08,
    "gp2": 0.10,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}
EBS_DEFAULT_GB_MONTH_USD = 0.10

PRICING_NOTE = "Costs are approximate list prices, not a bill."


def ebs_monthly_cost(volume_type: str, size_gb: int) -> float:
    """Return estimated monthly USD cost for an EBS volume."""

    rate = EBS_GB_MONTH_USD.get(volume_type, EBS_DEFAULT_GB_MONTH_USD)
    return round(size_gb * rate, 2)


def eip_monthly_cost() -> float:
    """Return estimated monthly USD cost for one Elastic IP / public IPv4 address."""

    return round(EIP_HOURLY_USD * HOURS_PER_MONTH, 2)
