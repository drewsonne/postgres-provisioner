"""Put controller/ on sys.path so tests can import its modules."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "controller"))
