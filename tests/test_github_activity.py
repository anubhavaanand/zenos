"""tools/github_activity.py asks GitHub again when its API answers with a server error for a moment."""
import importlib.util, io, os, unittest, urllib.error
from unittest import mock

spec = importlib.util.spec_from_file_location("github_activity", os.path.join(os.path.dirname(__file__), "..", "tools", "github_activity.py"))
ga = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ga)


def err(code):
    return urllib.error.HTTPError("https://api.github.com/x", code, "x", {}, io.BytesIO(b""))


class Retry(unittest.TestCase):
    def test_server_error_then_answer(self):
        calls = []

        def fake(req, timeout):
            calls.append(1)
            if len(calls) < 3:
                raise err(502)
            return io.BytesIO(b'{"ok": 1}')

        with mock.patch.object(ga.urllib.request, "urlopen", fake), mock.patch.object(ga.time, "sleep"):
            self.assertEqual(ga.get("/x"), {"ok": 1})
        self.assertEqual(len(calls), 3)

    def test_client_error_is_not_retried(self):
        calls = []

        def fake(req, timeout):
            calls.append(1)
            raise err(404)

        with mock.patch.object(ga.urllib.request, "urlopen", fake), mock.patch.object(ga.time, "sleep"):
            with self.assertRaises(urllib.error.HTTPError):
                ga.get("/x")
        self.assertEqual(len(calls), 1)

    def test_gives_up_after_four_tries(self):
        calls = []

        def fake(req, timeout):
            calls.append(1)
            raise err(503)

        with mock.patch.object(ga.urllib.request, "urlopen", fake), mock.patch.object(ga.time, "sleep"):
            with self.assertRaises(urllib.error.HTTPError):
                ga.get("/x")
        self.assertEqual(len(calls), 4)


if __name__ == "__main__":
    unittest.main()
