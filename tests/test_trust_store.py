import unittest
import sys
import os
import errno
from unittest.mock import patch, MagicMock

# Add controller dir to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))

# pyrefly: ignore [missing-import]
from trust import TrustStore, TrustEntry

class TestTrustStore(unittest.TestCase):
    def setUp(self):
        pass

    @patch('trust.bpf_syscall')
    def test_missing_entry_returns_100(self, mock_bpf):
        # Simulate map open succeeds, but lookup raises ENOENT
        mock_bpf.side_effect = [10, OSError(errno.ENOENT, "No such file or directory")]
        
        store = TrustStore()
        score = store.get("10.0.0.2")
        self.assertEqual(score, 100)

    @patch('trust.bpf_syscall')
    def test_existing_entry_returns_score(self, mock_bpf):
        # Simulate map open succeeds, and lookup populates score = 85
        def fake_syscall(cmd, attr_struct):
            if cmd == 7:  # BPF_OBJ_GET
                return 10
            elif cmd == 1:  # BPF_MAP_LOOKUP_ELEM
                # Populate value memory with score 85
                val_ptr = attr_struct.value
                val_obj = TrustEntry.from_address(val_ptr)
                val_obj.score = 85
                return 0
            return 0

        mock_bpf.side_effect = fake_syscall
        
        store = TrustStore()
        score = store.get("10.0.0.1")
        self.assertEqual(score, 85)

    @patch('trust.bpf_syscall')
    def test_map_unavailable_returns_100(self, mock_bpf):
        # Simulate map open failing
        mock_bpf.side_effect = OSError(errno.ENOENT, "No such file or directory")
        
        store = TrustStore()
        score = store.get("10.0.0.2")
        self.assertEqual(score, 100)

    @patch('trust.bpf_syscall')
    def test_bpf_other_error_returns_100(self, mock_bpf):
        # Simulate map open succeeds, but lookup fails with EPERM
        mock_bpf.side_effect = [10, OSError(errno.EPERM, "Operation not permitted")]
        
        store = TrustStore()
        score = store.get("10.0.0.1")
        self.assertEqual(score, 100)

if __name__ == '__main__':
    unittest.main()
