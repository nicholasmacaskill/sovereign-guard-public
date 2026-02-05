
import pytest
import os
import sys
import subprocess
import time
import threading
import http.server
import socketserver
from playwright.sync_api import sync_playwright

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

@pytest.fixture(scope="session")
def mock_server():
    """Starts a local HTTP server to serve test assets."""
    port = 8000
    assets_dir = os.path.join(os.path.dirname(__file__), 'assets')
    
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=assets_dir, **kwargs)
        def log_message(self, format, *args):
            pass # Silence logs

    httpd = socketserver.TCPServer(("", port), Handler)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()
    
    yield f"http://localhost:{port}"
    
    httpd.shutdown()

@pytest.fixture(scope="session")
def test_profile_dir():
    """Creates a temporary directory for the browser profile."""
    import tempfile
    import shutil
    tmp_dir = tempfile.mkdtemp()
    yield tmp_dir
    shutil.rmtree(tmp_dir)

@pytest.fixture(scope="session")
def guard_process(test_profile_dir):
    """Starts the Sovereign Guard monitor in a subprocess."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
    cmd = [sys.executable, 'src/guard_monitor.py']
    
    env = os.environ.copy()
    env['PROTECTION_MODE'] = 'protect' 
    env['SOVEREIGN_TEST_MODE'] = '1' 
    # Chrome creates a 'Default' profile inside the User Data Dir
    # We point the scanner to this specific profile for the test
    env['SOVEREIGN_TEST_BROWSER_DIR'] = os.path.join(test_profile_dir, 'Default')
    
    proc = subprocess.Popen(
        cmd, 
        cwd=root_dir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    time.sleep(3)
    yield proc
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()

@pytest.fixture(scope="session")
def browser_context(test_profile_dir):
    """Launches Playwright Chrome with persistent context."""
    with sync_playwright() as p:
        # Use persistent_context to ensure data is written to the monitored dir
        # We need remote-debugging-port=0 to trigger the analyzer logic check (random port)
        # But wait, logic says "If 9222 -> Kill".
        # If random, passes.
        
        browser = p.chromium.launch_persistent_context(
            user_data_dir=test_profile_dir,
            headless=False,
            permissions=['clipboard-read', 'clipboard-write'],
            args=['--remote-debugging-port=0'] # Explicitly ask for random port to verify analyzer allows it
        )
        yield browser
        browser.close()
