import random
from pathlib import Path

import pytest

from siemlab.simulate.world import World, build_world

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"


@pytest.fixture(scope="session")
def world() -> World:
    return build_world(seed=3)


@pytest.fixture
def rng() -> random.Random:
    return random.Random(11)


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    return RULES
