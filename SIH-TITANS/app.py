import sys
from pathlib import Path

# Add sih directory to python path
sys.path.insert(0, str(Path(__file__).parent / "sih"))

from sih.backend.app import app

if __name__ == "__main__":
    app.run()
