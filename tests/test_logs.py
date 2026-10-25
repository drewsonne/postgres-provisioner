"""Tests for the JSON log formatter."""

import json
import logging
import sys

import pytest
from logs import JsonFormatter, configure_logging


def make_record(**extra: object) -> logging.LogRecord:
    record = logging.LogRecord(
        "kopf.objects", logging.INFO, "f", 1, "hi %s", ("x",), None
    )
    record.__dict__.update(extra)
    return record


def test_record_is_one_line_with_workgraph_keys() -> None:
    line = JsonFormatter().format(make_record())
    assert "\n" not in line
    assert set(json.loads(line)) == {"time", "level", "logger", "message"}
    assert json.loads(line)["message"] == "hi x"


def test_exc_with_exc_info() -> None:
    try:
        raise ValueError("boom")  # noqa: EM101, TRY301
    except ValueError:
        record = make_record(exc_info=sys.exc_info())
    assert "ValueError: boom" in json.loads(JsonFormatter().format(record))["exc"]


@pytest.mark.parametrize(
    ("ref", "expected"),
    [({"namespace": "ns", "name": "db"}, "ns/db"), ({"name": "db"}, "db")],
)
def test_object_from_k8s_ref(ref: dict[str, str], expected: str) -> None:
    entry = json.loads(JsonFormatter().format(make_record(k8s_ref=ref)))
    assert entry["object"] == expected


def test_configure_logging_replaces_root_handlers() -> None:
    root = logging.getLogger()
    saved = root.handlers[:]
    try:
        root.addHandler(logging.NullHandler())
        configure_logging()
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
    finally:
        root.handlers[:] = saved
