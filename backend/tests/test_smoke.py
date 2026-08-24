"""Smoke tests — verify imports and basic schema loading."""
import importlib


def test_import_main():
    mod = importlib.import_module("app.main")
    assert hasattr(mod, "app")


def test_import_models():
    mod = importlib.import_module("app.models")
    assert hasattr(mod, "User")
    assert hasattr(mod, "Alert")
    assert hasattr(mod, "Device")


def test_import_schemas():
    mod = importlib.import_module("app.schemas")
    assert hasattr(mod, "AlertResponse")
    assert hasattr(mod, "IngestAlertBatch")


def test_import_broadcaster():
    mod = importlib.import_module("app.broadcaster")
    assert hasattr(mod, "broadcaster")
