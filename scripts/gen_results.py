#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"src"))
from keycloakjwt.cli import _write_results
_write_results(Path(sys.argv[1]) if len(sys.argv)>1 else Path("results"))
