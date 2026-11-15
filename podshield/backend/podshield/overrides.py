"""Rule overrides made through the API, layered on top of config.toml.

Precedence for a rule: API/database override > config file > rule default. Both the API and
the CLI apply the stored overrides, so a rule disabled in the UI is also skipped by the
nightly ``podshield scan`` timer.
"""

from __future__ import annotations

import threading

from sqlalchemy import Engine
from sqlmodel import Session, select

from podshield.config import RuleOverride, Settings
from podshield.models import RuleOverrideRecord
from podshield.schemas import Severity


class RuleStore:
    """Keeps ``settings.rules`` equal to (config file rules + stored overrides)."""

    def __init__(self, settings: Settings, engine: Engine) -> None:
        self.settings = settings
        self.engine = engine
        self._baseline = {k: v.model_copy() for k, v in settings.rules.items()}
        self._lock = threading.Lock()
        self.reload()

    def reload(self) -> None:
        merged = {k: v.model_copy() for k, v in self._baseline.items()}
        with Session(self.engine) as session:
            for rec in session.exec(select(RuleOverrideRecord)):
                current = merged.get(rec.rule_id, RuleOverride())
                merged[rec.rule_id] = RuleOverride(
                    enabled=rec.enabled if rec.enabled is not None else current.enabled,
                    severity=Severity(rec.severity) if rec.severity else current.severity,
                )
        # Swap the whole dict in one assignment so a scan running in another thread never
        # sees a half-updated rule set. Everything holds the Settings object, not the dict.
        self.settings.rules = merged

    def update(
        self,
        rule_id: str,
        *,
        enabled: bool | None,
        severity: Severity | None,
        fields: set[str],
    ) -> None:
        """Persist a change. Only names in ``fields`` are touched; ``None`` for a touched
        field clears the override and falls back to the config-file value."""
        with self._lock, Session(self.engine) as session:
            rec = session.get(RuleOverrideRecord, rule_id)
            exists = rec is not None
            rec = rec or RuleOverrideRecord(rule_id=rule_id)
            if "enabled" in fields:
                rec.enabled = enabled
            if "severity" in fields:
                rec.severity = severity.value if severity else None
            if rec.enabled is None and rec.severity is None:
                if exists:
                    session.delete(rec)
            else:
                session.add(rec)
            session.commit()
            self.reload()


def apply_rule_overrides(settings: Settings, engine: Engine) -> RuleStore:
    """Merge stored overrides into ``settings.rules`` (used by the CLI)."""
    return RuleStore(settings, engine)
