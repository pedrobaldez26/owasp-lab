import pytest

from app import create_app


@pytest.fixture()
def app():
    return create_app({"TESTING": True, "PASSWORD_HASH_METHOD": "pbkdf2:sha256:1000"})  # poucas iterações: teste rápido


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, mode, username, password):
    return client.post(f"/{mode}/login", data={"username": username, "password": password})
