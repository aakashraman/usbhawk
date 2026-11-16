import os
from datetime import datetime, timezone

import pytest

DATA = os.path.join(os.path.dirname(__file__), "data")


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


def sample(name):
    """Real-world sample artifacts are downloaded by scripts/fetch_test_samples.py."""
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        pytest.skip(f"sample {name} not present - run: python scripts/fetch_test_samples.py")
    return path
