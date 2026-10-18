"""Versioned surface counts. Candidate objects are not confirmed services.

Legacy total_entries/entry_points/total_entry_points count candidates. Missing
evidence levels stay unknown; names and confidence never supply evidence.
"""
from __future__ import annotations

from typing import Any

EVIDENCE_LEVELS = {
    "file_or_symlink_observed", "api_symbol_observed", "heuristic_only",
    "runtime_confirmed", "unknown",
}
COUNT_FIELDS = (
    "candidate_entries_total", "file_or_symlink_candidates",
    "api_inferred_candidates", "heuristic_candidates", "runtime_confirmed_entries",
    "unknown_evidence_candidates", "route_mappings_total", "http_route_candidates",
)


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def surface_counts(summary: Any = None, entries: Any = None, routes: Any = None) -> dict[str, Any]:
    """Prefer actual lists; retain conflicting legacy declarations as diagnostics.

    None means unavailable, [] means observed empty. Unknown evidence levels are
    counted separately, never upgraded to observed or runtime evidence.
    """
    summary = summary if isinstance(summary, dict) else {}
    result = {key: _count(summary.get(key)) for key in COUNT_FIELDS}
    declarations = {key: _count(summary.get(key)) for key in (
        "candidate_entries_total", "total_entries", "entry_points", "total_entry_points"
    ) if _count(summary.get(key)) is not None}
    total = next(iter(declarations.values()), None)
    observed = isinstance(entries, list) and all(isinstance(item, dict) for item in entries)
    if observed:
        total = len(entries)
        levels = [item.get("evidence_level", "unknown") for item in entries]
        for key, level in (
            ("file_or_symlink_candidates", "file_or_symlink_observed"),
            ("api_inferred_candidates", "api_symbol_observed"),
            ("heuristic_candidates", "heuristic_only"),
        ):
            result[key] = levels.count(level)
        result["unknown_evidence_candidates"] = sum(level not in EVIDENCE_LEVELS or level == "unknown" for level in levels)
        result["runtime_confirmed_entries"] = sum(item.get("runtime_confirmed") is True for item in entries)
        result["http_route_candidates"] = sum(item.get("entry_type") == "http_route" for item in entries)
    result["candidate_entries_total"] = total
    result["route_mappings_total"] = len(routes) if isinstance(routes, list) else (
        result["route_mappings_total"] if result["route_mappings_total"] is not None else _count(summary.get("route_entries"))
    )
    result["count_status"] = "observed_list" if observed else ("summary_only" if total is not None else "unknown")
    result["count_disagreements"] = {key: value for key, value in declarations.items() if value != total}
    if observed:
        for key in COUNT_FIELDS:
            declared = _count(summary.get(key))
            if declared is not None and result[key] is not None and declared != result[key]:
                result["count_disagreements"][key] = declared
    return result


def surface_summary(summary: Any = None, entries: Any = None, routes: Any = None) -> dict[str, Any]:
    """Add explicit metrics without rewriting the meaning of historical keys."""
    original = dict(summary) if isinstance(summary, dict) else {}
    counts = surface_counts(original, entries, routes)
    # total_entries remains the canonical legacy alias for candidate objects.
    original.setdefault("total_entries", counts["candidate_entries_total"])
    return {**original, **counts, "count_schema_version": "firmxplore.surface.counts.v2"}
