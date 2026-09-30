import hashlib


def test_md5_fixture():
    assert hashlib.md5(b"x").hexdigest()
