"""
E2E Tests for Injection Defense
--------------------------------
Tests memory scanning, binary integrity, module verification,
Launch Services monitoring, and keychain access analysis.
"""

import pytest
import os
import sys
import time
import hashlib
import shutil
import tempfile
from unittest.mock import Mock, patch, MagicMock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from sovereign_engine import injection_defense, patterns


class TestBinaryIntegrity:
    """Test binary integrity verification system."""
    
    def test_calculate_file_hash(self, tmp_path):
        """Test file hash calculation."""
        test_file = tmp_path / "test_binary"
        test_file.write_text("test content for hashing")
        
        hash_result = injection_defense.calculate_file_hash(str(test_file))
        
        # Verify it's a valid SHA-256 hash (64 hex characters)
        assert hash_result is not None
        assert len(hash_result) == 64
        assert all(c in '0123456789abcdef' for c in hash_result)
    
    def test_binary_integrity_baseline_creation(self, tmp_path):
        """Test that first run creates a baseline hash."""
        # Reset baselines
        injection_defense.reset_baselines()
        
        # Create a fake browser binary
        fake_chrome = tmp_path / "Google Chrome"
        fake_chrome.write_text("fake chrome binary content")
        
        # Add to patterns temporarily
        original_hashes = patterns.BROWSER_BINARY_HASHES.copy()
        patterns.BROWSER_BINARY_HASHES[str(fake_chrome)] = None
        
        try:
            # First verification should establish baseline
            threats = injection_defense.verify_binary_integrity()
            
            # Should not detect threats on first run
            assert len(threats) == 0
            
            # Hash should now be populated
            assert patterns.BROWSER_BINARY_HASHES[str(fake_chrome)] is not None
            
        finally:
            patterns.BROWSER_BINARY_HASHES = original_hashes
    
    def test_binary_tampering_detection(self, tmp_path):
        """Test detection of tampered binaries."""
        injection_defense.reset_baselines()
        
        # Create a fake browser binary
        fake_chrome = tmp_path / "Google Chrome"
        fake_chrome.write_text("original content")
        
        # Calculate initial hash
        original_hash = injection_defense.calculate_file_hash(str(fake_chrome))
        
        # Set up patterns with the original hash
        original_hashes = patterns.BROWSER_BINARY_HASHES.copy()
        patterns.BROWSER_BINARY_HASHES[str(fake_chrome)] = original_hash
        
        try:
            # Modify the binary
            fake_chrome.write_text("TAMPERED CONTENT - MALWARE INJECTED")
            
            # Clear cache to force re-check
            injection_defense._binary_hash_cache.clear()
            
            # Verification should detect the tampering
            threats = injection_defense.verify_binary_integrity()
            
            assert len(threats) == 1
            assert threats[0]['type'] == 'BINARY_TAMPERING'
            assert threats[0]['severity'] == 'CRITICAL'
            assert 'modified' in threats[0]['summary'].lower()
            
        finally:
            patterns.BROWSER_BINARY_HASHES = original_hashes


class TestMemoryScanning:
    """Test process memory scanning for injections."""
    
    @patch('subprocess.run')
    def test_memory_scan_clean_process(self, mock_run):
        """Test that clean browser process passes memory scan."""
        # Mock clean vmmap output
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""
            __TEXT r-x /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
            __DATA rw- /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
            Stack  rw- [stack]
            """
        )
        
        mock_proc = Mock()
        mock_proc.pid = 12345
        mock_proc.name.return_value = "Google Chrome"
        
        threat = injection_defense.scan_process_memory(mock_proc)
        
        # Clean process should return None
        assert threat is None
    
    @patch('subprocess.run')
    def test_memory_scan_rwx_region(self, mock_run):
        """Test detection of suspicious RWX memory regions."""
        # Mock vmmap output with RWX region (highly suspicious)
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""
            __TEXT r-x /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
            MALLOC rwx 0x7f8000000000-0x7f8001000000  [suspicious]
            """
        )
        
        mock_proc = Mock()
        mock_proc.pid = 12345
        mock_proc.name.return_value = "Google Chrome"
        
        threat = injection_defense.scan_process_memory(mock_proc)
        
        # Should detect RWX region
        assert threat is not None
        assert threat['type'] == 'MEMORY_INJECTION'
        assert threat['severity'] == 'CRITICAL'
    
    @patch('subprocess.run')
    def test_memory_scan_executable_heap(self, mock_run):
        """Test detection of executable permissions on heap."""
        # Mock vmmap output with executable heap (classic injection)
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""
            __TEXT r-x /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
            heap   r-x 0x7f8000000000-0x7f8001000000
            """
        )
        
        mock_proc = Mock()
        mock_proc.pid = 12345
        mock_proc.name.return_value = "Brave Browser"
        
        threat = injection_defense.scan_process_memory(mock_proc)
        
        # Should detect executable heap
        assert threat is not None
        assert threat['type'] == 'MEMORY_INJECTION'


class TestModuleVerification:
    """Test module/library verification."""
    
    @patch('subprocess.run')
    def test_module_verification_clean(self, mock_run):
        """Test that legitimate libraries pass verification."""
        # Mock lsof output with only trusted libraries
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""
            chrome 12345 /System/Library/Frameworks/CoreFoundation.framework
            chrome 12345 /Applications/Google Chrome.app/Contents/Frameworks/Chrome Helper.dylib
            """
        )
        
        mock_proc = Mock()
        mock_proc.pid = 12345
        mock_proc.name.return_value = "Google Chrome"
        
        threat = injection_defense.verify_process_modules(mock_proc)
        
        # Trusted modules should pass
        assert threat is None
    
    @patch('sovereign_engine.injection_defense.subprocess.run')
    def test_module_verification_suspicious(self, mock_run):
        """Test detection of untrusted libraries from suspicious locations."""
        # Mock lsof output with library from /tmp (highly suspicious)
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""
chrome 12345 user 123r REG 1,4 12345 12345 /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
chrome 12345 user 124r REG 1,4 12345 12345 /tmp/malicious_injector.dylib
            """
        )
        
        mock_proc = Mock()
        mock_proc.pid = 12345
        mock_proc.name.return_value = "Google Chrome"
        
        threat = injection_defense.verify_process_modules(mock_proc)
        
        # Should detect suspicious library
        assert threat is not None
        assert threat['type'] == 'MODULE_INJECTION'
        assert '/tmp/malicious_injector.dylib' in str(threat['libraries'])


class TestLaunchServices:
    """Test Launch Services monitoring."""
    
    @patch('subprocess.run')
    def test_launch_services_baseline(self, mock_run):
        """Test baseline establishment for Launch Services."""
        injection_defense.reset_baselines()
        
        # Mock defaults output
        mock_run.return_value = Mock(
            returncode=0,
            stdout="""
            LSHandlers = (
                { LSHandlerURLScheme = http; LSHandlerRoleAll = com.google.chrome; }
            )
            """
        )
        
        threats = injection_defense.check_launch_services()
        
        # First run should not detect threats
        assert len(threats) == 0
    
    @patch('subprocess.run')
    def test_launch_services_hijacking(self, mock_run):
        """Test detection of browser handler changes."""
        injection_defense.reset_baselines()
        
        # First call - establish baseline
        mock_run.return_value = Mock(
            returncode=0,
            stdout="http com.google.chrome"
        )
        injection_defense.check_launch_services()
        
        # Second call - handler changed (possible hijack)
        mock_run.return_value = Mock(
            returncode=0,
            stdout="http com.malware.fakebrowser"
        )
        threats = injection_defense.check_launch_services()
        
        # Should detect the change
        assert len(threats) > 0
        assert threats[0]['type'] == 'LAUNCH_SERVICES_HIJACK'


class TestKeychainMonitoring:
    """Test keychain access monitoring."""
    
    @patch('psutil.process_iter')
    def test_keychain_normal_access(self, mock_iter):
        """Test that normal keychain access doesn't trigger alerts."""
        injection_defense.reset_baselines()
        
        # Mock a browser process with keychain file open
        mock_proc = Mock()
        mock_proc.info = {'pid': 12345, 'name': 'Google Chrome'}
        mock_proc.open_files.return_value = [
            Mock(path='/Users/test/Library/Keychains/login.keychain-db')
        ]
        
        mock_iter.return_value = [mock_proc]
        
        # Normal access (under threshold)
        threats = injection_defense.monitor_keychain_access()
        
        # Should not alert for browser
        assert len(threats) == 0
    
    @patch('psutil.process_iter')
    def test_keychain_excessive_access(self, mock_iter):
        """Test detection of excessive keychain access."""
        injection_defense.reset_baselines()
        
        # Mock a suspicious process with keychain file open
        mock_proc = Mock()
        mock_proc.info = {'pid': 99999, 'name': 'suspicious_app'}
        mock_proc.open_files.return_value = [
            Mock(path='/Users/test/Library/Keychains/login.keychain-db')
        ]
        
        mock_iter.return_value = [mock_proc]
        
        # Simulate excessive access by calling multiple times
        for _ in range(patterns.MAX_KEYCHAIN_READS_PER_MINUTE + 5):
            injection_defense.monitor_keychain_access()
        
        threats = injection_defense.monitor_keychain_access()
        
        # Should detect excessive access
        assert len(threats) > 0
        assert threats[0]['type'] == 'EXCESSIVE_KEYCHAIN_ACCESS'
        assert threats[0]['process'] == 'suspicious_app'


class TestIntegration:
    """Integration tests for the full injection defense system."""
    
    def test_reset_baselines(self):
        """Test that baseline reset clears all state."""
        # Populate some state
        injection_defense._binary_hash_cache['test'] = ('hash', time.time())
        injection_defense._keychain_access_log[123] = [(time.time(), 'test')]
        injection_defense._last_launch_services_state = {'http': 'test'}
        
        # Reset
        injection_defense.reset_baselines()
        
        # Verify all cleared
        assert len(injection_defense._binary_hash_cache) == 0
        assert len(injection_defense._keychain_access_log) == 0
        assert injection_defense._last_launch_services_state is None
    
    def test_feature_flags(self):
        """Test that feature flags control execution."""
        # Verify flags can be set
        assert isinstance(patterns.ENABLE_MEMORY_SCANNING, bool)
        assert isinstance(patterns.ENABLE_BINARY_VERIFICATION, bool)
        assert isinstance(patterns.ENABLE_LAUNCH_SERVICES_MONITOR, bool)
        assert isinstance(patterns.ENABLE_KEYCHAIN_MONITORING, bool)
    
    def test_configuration_intervals(self):
        """Test that scan intervals are configurable."""
        assert patterns.MEMORY_SCAN_INTERVAL >= 0
        assert patterns.INTEGRITY_CHECK_INTERVAL >= 0
        assert patterns.LAUNCH_SERVICES_CHECK_INTERVAL >= 0
        assert patterns.KEYCHAIN_MONITOR_INTERVAL >= 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
