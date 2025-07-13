# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

import os
import pytest

# Automatically set the test environment before running tests / Umgebung automatisch auf "test" setzen, bevor Tests ausgeführt werden
@pytest.fixture(scope="session", autouse=True)
def configure_test_environment():
    os.environ["ENV"] = "test"

    # Ensure that the static directory exists for test runs / Sicherstellen, dass der statische Ordner für Tests vorhanden ist
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    static_path = os.path.join(base_dir, "static")
    os.makedirs(static_path, exist_ok=True)