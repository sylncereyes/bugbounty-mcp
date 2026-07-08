from unittest.mock import MagicMock
from tools.a09_logging import _content_matches_endpoint

def test_soft_404_not_flagged_as_actuator():
    fake_res = MagicMock()
    fake_res.text = '<html><body>Welcome to DQLab</body></html>'
    fake_res.headers = {}
    assert _content_matches_endpoint('/actuator', fake_res) is False

def test_real_actuator_response_flagged():
    real_res = MagicMock()
    real_res.text = '{"_links": {"self": {}}}'
    real_res.headers = {}
    assert _content_matches_endpoint('/actuator', real_res) is True

def test_soft_404_not_flagged_as_phpinfo():
    fake_res = MagicMock()
    fake_res.text = '<html><body>Welcome to DQLab</body></html>'
    fake_res.headers = {}
    assert _content_matches_endpoint('/phpinfo.php', fake_res) is False