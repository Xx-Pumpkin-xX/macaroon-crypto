"""Run local adversarial scenarios, emit reviewable JUnit evidence.

No remote requests, credentials, token values or uploaded data are persisted.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == '__main__':
    result_dir = ROOT / 'tests/results'
    result_dir.mkdir(exist_ok=True)
    result = subprocess.run([
        sys.executable, '-m', 'pytest', str(ROOT / 'tests/test_acceptance.py'),
        '-q', '-k', 'hostile or escalate or expiry or revocation or guessed or share_matrix or remove_each',
        '--junitxml=' + str(result_dir / 'attacks.xml'),
    ], cwd=ROOT)
    sys.exit(result.returncode)
