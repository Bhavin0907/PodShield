from __future__ import annotations

import pytest
from sqlalchemy import Engine

from podshield import main
from podshield.config import Settings


def test_importing_main_does_not_create_an_app_or_database() -> None:
    assert not hasattr(main, "app")


def test_default_app_reads_settings(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, engine: Engine, tmp_path: object
) -> None:
    settings.database.path = str(tmp_path) + "/default.db"  # type: ignore[operator]
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    app = main.create_default_app()
    assert app.title == "PodShield"
    assert app.state.settings is settings
