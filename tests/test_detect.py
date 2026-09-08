import unittest
from src.detect import analyze_events


class DetectionTests(unittest.TestCase):
    def test_correlated_remote_activity_is_high(self):
        events = [
            {"source_host":"A","destination_host":"B","event_type":"remote_logon","user":"u"},
            {"source_host":"A","destination_host":"B","event_type":"admin_share_access","user":"u"},
            {"source_host":"A","destination_host":"B","event_type":"remote_process","user":"u"},
        ]
        result = analyze_events(events)[0]
        self.assertEqual(result["severity"], "High")
        self.assertEqual(result["score"], 9)

    def test_single_remote_logon_is_low(self):
        events = [{"source_host":"A","destination_host":"B","event_type":"remote_logon","user":"u"}]
        result = analyze_events(events)[0]
        self.assertEqual(result["severity"], "Low")


if __name__ == "__main__":
    unittest.main()
