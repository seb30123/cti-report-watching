"""
pytest configuration — adds project root to sys.path so imports work cleanly.
"""
import sys
from pathlib import Path

# Make sure 'app' is importable from tests/
sys.path.insert(0, str(Path(__file__).parent.parent))
