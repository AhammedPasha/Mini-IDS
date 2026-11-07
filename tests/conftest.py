import os
import tempfile
from pathlib import Path

# Test-only API token. Never use the real application token here.
os.environ["IDS_INTERNAL_API_TOKEN"] = "mini-ids-test-token"

# Give tests their own isolated database.
from ids import database

test_directory = Path(tempfile.mkdtemp(prefix="mini_ids_tests_"))
database.DB_PATH = test_directory / "test_database.db"

# Create the database tables before API tests execute.
database.initialize_database()
