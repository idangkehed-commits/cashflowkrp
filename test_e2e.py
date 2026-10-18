"""Run the current email-auth and operational regression suite."""
import runpy
from pathlib import Path

if __name__ == '__main__':
    runpy.run_path(str(Path(__file__).with_name('test_auth.py')), run_name='__main__')
