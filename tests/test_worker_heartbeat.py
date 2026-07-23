import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stacks.coordinator import database  # noqa: E402
from stacks.coordinator.download_worker import _heartbeat_loop  # noqa: E402
from stacks.coordinator.queue_ops import QueueOperations  # noqa: E402


class WorkerHeartbeatTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.original_database_path = database.DATABASE_PATH
        self.original_runtime_path = database.RUNTIME_PATH
        self.original_heartbeat_path = database.HEARTBEAT_DATABASE_PATH
        database.DATABASE_PATH = root / "config" / "queue.db"
        database.RUNTIME_PATH = root / "runtime"
        database.HEARTBEAT_DATABASE_PATH = database.RUNTIME_PATH / "heartbeats.db"
        database.init_database()
        database.startup_cleanup()

    def tearDown(self):
        database.DATABASE_PATH = self.original_database_path
        database.RUNTIME_PATH = self.original_runtime_path
        database.HEARTBEAT_DATABASE_PATH = self.original_heartbeat_path
        self.temp_dir.cleanup()

    def test_heartbeat_stays_fresh_while_worker_is_blocked(self):
        operations = QueueOperations()
        stop_event = threading.Event()

        def last_seen():
            conn = database.get_heartbeat_connection()
            try:
                row = conn.execute(
                    "SELECT last_seen FROM worker_heartbeats WHERE worker_id = ?",
                    ("download-0",),
                ).fetchone()
                return row[0] if row else None
            finally:
                conn.close()

        with patch("stacks.coordinator.queue_ops.WORKER_HEARTBEAT_INTERVAL", 0.01):
            heartbeat_thread = threading.Thread(
                target=_heartbeat_loop,
                args=(operations, "download-0", stop_event, 0.01),
            )
            heartbeat_thread.start()
            try:
                deadline = time.monotonic() + 1
                while last_seen() is None and time.monotonic() < deadline:
                    time.sleep(0.005)
                first_seen = last_seen()
                self.assertIsNotNone(first_seen)

                # Simulate a synchronous operation that outlasts the stale
                # threshold and never invokes the normal progress callback.
                time.sleep(0.08)
                self.assertGreater(last_seen(), first_seen)
                self.assertNotIn(
                    "download-0",
                    operations.get_stale_workers(timeout_seconds=0.03),
                )
            finally:
                stop_event.set()
                heartbeat_thread.join(timeout=1)

        self.assertFalse(heartbeat_thread.is_alive())
        time.sleep(0.04)
        self.assertIn(
            "download-0",
            operations.get_stale_workers(timeout_seconds=0.03),
        )


if __name__ == "__main__":
    unittest.main()
