# Copyright (c) 2025 Joël Krügel
# License: GPL-3.0
# See LICENSE file in the project root for details.

import os
import pytest

# Temporary class to ensure static folder exists / Temporäre Klasse, um sicherzustellen, dass die statische Ordnerstruktur existiert
@pytest.fixture(scope="session", autouse=True)
def ensure_static_folder_exists():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    static_path = os.path.join(base_dir, "static")
    os.makedirs(static_path, exist_ok=True)

