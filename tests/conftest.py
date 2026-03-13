"""
Shared test fixtures for BBRadar test suite.
"""

import os
import tempfile
import pytest

from bbradar.core.database import init_db, get_db_path


@pytest.fixture
def tmp_db(tmp_path):
    """Provide a fresh temporary database for each test."""
    db_path = tmp_path / "test.db"
    init_db(db_path)
    return str(db_path)
