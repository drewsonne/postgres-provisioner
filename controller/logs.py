"""One JSON object per log line, with the same keys as the workgraph services."""

import json
import logging


class JsonFormatter(logging.Formatter):
    """Format a record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        """Return the record as JSON with time, level, logger and message."""
        entry: dict[str, str] = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # kopf's per-object logger sets k8s_ref; keep saying which resource.
        ref = getattr(record, "k8s_ref", None)
        if ref and ref.get("name"):
            namespace = ref.get("namespace")
            name = ref["name"]
            entry["object"] = f"{namespace}/{name}" if namespace else name
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def configure_logging() -> None:
    """Replace the root handlers (kopf's included) with one JSON handler."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logging.getLogger().handlers[:] = [handler]
