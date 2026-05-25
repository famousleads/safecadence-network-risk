"""
v14.1 — Predictive risk forecasting.

Reads from the ``ReferenceCorpus`` (which already blends local +
baseline) and fits a simple ordinary-least-squares (OLS) linear
regression through the customer's last-30-day series. Returns:

  * A point forecast for the next N days
  * 90% confidence interval (computed from the residual standard error)
  * The slope ("trajectory") and an English interpretation
  * A ``data_source_breakdown`` field passed straight through from
    the corpus so the caller / customer / auditor sees exactly what
    fed the forecast.

Why OLS and not ARIMA / Prophet / Transformer
---------------------------------------------

* No external dependencies. SafeCadence stays stdlib-only.
* Honest: the data is daily, the windows are 30 days, and the most
  useful question is "is the trend up or down" — OLS answers that
  exactly. Heavier models would invent precision the data doesn't
  support.
* When the customer has < ``MIN_LOCAL_DAYS`` days of their own data,
  the series is 100% baseline (a flat line), so the slope is zero
  and the forecast band is honest about how little we know.

Public API
----------

* ``forecast_metric(corpus, metric, horizon_days=14, ci=0.90)``
    → ``{
         "metric", "horizon_days", "ci",
         "current", "forecast", "ci_low", "ci_high",
         "slope_per_day", "trajectory", "interpretation",
         "data_source_breakdown", "citation",
         "warnings": [...]
       }``
"""
from __future__ import annotations

import math
from typing import Any

from safecadence.intelligence.corpus import (
    LOCAL_PRIMARY_DAYS,
    MIN_LOCAL_DAYS,
    ReferenceCorpus,
)


# Two-tailed t-distribution critical values for small samples. We use
# the 28-df row (matches our default 30-day window minus 2 dof for
# slope + intercept) which is conservative across our range.
_T_CRITICAL = {
    0.80: 1.313,
    0.90: 1.701,
    0.95: 2.048,
    0.99: 2.763,
}


def _ols_fit(xs: list[float], ys: list[float]) -> tuple[float, float, float]:
    """Plain ordinary-least-squares. Returns (slope, intercept, residual_se)."""
    n = len(xs)
    if n < 2:
        return 0.0, (ys[0] if ys else 0.0), 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
    den = sum((xs[i] - mean_x) ** 2 for i in range(n))
    if den == 0:
        return 0.0, mean_y, 0.0
    slope = num / den
    intercept = mean_y - slope * mean_x
    # Residual standard error.
    residuals = [ys[i] - (intercept + slope * xs[i]) for i in range(n)]
    if n <= 2:
        return slope, intercept, 0.0
    rss = sum(r * r for r in residuals)
    se = math.sqrt(rss / max(1, (n - 2)))
    return slope, intercept, se


def _trajectory_word(slope: float, metric: str) -> str:
    """Map slope sign to plain English. Higher-is-better metrics
    (safe_score, mfa_coverage_pct) read the slope inverted."""
    higher_is_better = metric in {"safe_score", "mfa_coverage_pct"}
    if abs(slope) < 1e-6:
        return "stable"
    if slope > 0:
        return "improving" if higher_is_better else "worsening"
    return "worsening" if higher_is_better else "improving"


def _interpretation(
    metric: str, current: float, forecast: float, slope: float,
    days_local: int,
) -> str:
    direction = _trajectory_word(slope, metric)
    pct_change = ((forecast - current) / current * 100) if current else 0
    confidence_phrase = (
        "low-confidence (mostly baseline data)"
        if days_local < MIN_LOCAL_DAYS else
        "high-confidence (your own history)"
        if days_local >= LOCAL_PRIMARY_DAYS else
        "moderate-confidence (blended local + baseline)"
    )
    return (
        f"{metric} is {direction} (slope {slope:+.3f}/day). "
        f"Forecast {forecast:.1f} vs current {current:.1f} "
        f"({pct_change:+.1f}%). {confidence_phrase}."
    )


def forecast_metric(
    corpus: ReferenceCorpus,
    metric: str,
    *,
    horizon_days: int = 14,
    ci: float = 0.90,
) -> dict:
    """Forecast one metric. Always returns a dict, never raises."""
    warnings: list[str] = []
    series = corpus.get_series(metric)
    points = series["values"]
    if not points:
        return {
            "metric": metric,
            "horizon_days": horizon_days,
            "ci": ci,
            "current": None,
            "forecast": None,
            "ci_low": None,
            "ci_high": None,
            "slope_per_day": 0.0,
            "trajectory": "unknown",
            "interpretation": "No data available for this metric.",
            "data_source_breakdown": series["data_source_breakdown"],
            "citation": series["citation"],
            "warnings": ["empty_series"],
        }

    xs = [float(p["day"]) for p in points]
    ys = [float(p["v"]) for p in points]
    slope, intercept, se = _ols_fit(xs, ys)
    current = ys[-1]
    forecast_x = xs[-1] + horizon_days
    forecast_y = intercept + slope * forecast_x

    t_crit = _T_CRITICAL.get(ci, _T_CRITICAL[0.90])
    # Prediction-interval width grows with horizon. Conservative
    # multiplier reflects extrapolation uncertainty.
    pi_width = t_crit * se * math.sqrt(1 + (horizon_days / 30.0))
    ci_low = forecast_y - pi_width
    ci_high = forecast_y + pi_width

    days_local = series["data_source_breakdown"].get("days_local", 0)
    if days_local < MIN_LOCAL_DAYS:
        warnings.append(
            f"local_data_thin ({days_local}d < {MIN_LOCAL_DAYS}d threshold)"
        )

    interp = _interpretation(metric, current, forecast_y, slope, days_local)

    return {
        "metric": metric,
        "horizon_days": horizon_days,
        "ci": ci,
        "current": round(current, 3),
        "forecast": round(forecast_y, 3),
        "ci_low": round(ci_low, 3),
        "ci_high": round(ci_high, 3),
        "slope_per_day": round(slope, 5),
        "trajectory": _trajectory_word(slope, metric),
        "interpretation": interp,
        "data_source_breakdown": series["data_source_breakdown"],
        "citation": series["citation"],
        "warnings": warnings,
    }


def forecast_many(
    corpus: ReferenceCorpus,
    metrics: list[str] | None = None,
    *,
    horizon_days: int = 14,
    ci: float = 0.90,
) -> dict:
    """Convenience: forecast a batch of metrics. Returns {metric: result}."""
    from safecadence.intelligence.corpus import KNOWN_METRICS
    mets = metrics or list(KNOWN_METRICS)
    return {
        m: forecast_metric(corpus, m, horizon_days=horizon_days, ci=ci)
        for m in mets
    }


__all__ = ["forecast_metric", "forecast_many"]
