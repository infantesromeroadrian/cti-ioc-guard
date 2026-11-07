import json
import sys
import types

import httpx
import pytest

from cti_guard.infrastructure.adapters.llm.clients import (
    CachingClient,
    LLMError,
    OllamaClient,
    OpenAICompatClient,
    build_client,
)
from fakes import FakeLLM

SCHEMA = {"type": "object"}


def test_openai_compat_sends_max_tokens_not_max_completion_tokens():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(
            200, json={"choices": [{"message": {"content": '{"indicators": []}'}}]}
        )

    client = OpenAICompatClient("m", "http://x/v1", "k", transport=httpx.MockTransport(handler))
    assert client.chat_json("s", "u", SCHEMA, 321) == '{"indicators": []}'
    assert seen["body"]["max_tokens"] == 321
    assert "max_completion_tokens" not in seen["body"]
    assert seen["body"]["temperature"] == 0
    assert seen["auth"] == "Bearer k"


def test_openai_compat_wraps_http_errors():
    transport = httpx.MockTransport(lambda r: httpx.Response(500))
    with pytest.raises(LLMError):
        OpenAICompatClient("m", "http://x/v1", transport=transport).chat_json("s", "u", SCHEMA, 10)


def test_ollama_client_applies_num_predict_and_auth_header(monkeypatch):
    captured = {}

    class FakeOllama:
        def __init__(self, host, headers, timeout):
            captured["init"] = (host, headers, timeout)

        def chat(self, **kwargs):
            captured["chat"] = kwargs
            return types.SimpleNamespace(message=types.SimpleNamespace(content="{}"))

    monkeypatch.setitem(sys.modules, "ollama", types.SimpleNamespace(Client=FakeOllama))
    client = OllamaClient("gpt-oss:120b-cloud", "https://ollama.com", "secret", 30, think="low")
    assert client.chat_json("sys", "usr", SCHEMA, 555) == "{}"
    assert captured["init"][1] == {"Authorization": "Bearer secret"}
    assert captured["chat"]["options"]["num_predict"] == 555
    assert captured["chat"]["options"]["temperature"] == 0
    assert captured["chat"]["format"] == SCHEMA
    assert captured["chat"]["think"] == "low"


def test_ollama_client_without_key_sends_no_auth_header(monkeypatch):
    captured = {}

    class FakeOllama:
        def __init__(self, host, headers, timeout):
            captured["headers"] = headers

    monkeypatch.setitem(sys.modules, "ollama", types.SimpleNamespace(Client=FakeOllama))
    OllamaClient("m")
    assert captured["headers"] is None


def test_ollama_errors_are_wrapped(monkeypatch):
    class Boom:
        def __init__(self, **_):
            pass

        def chat(self, **_):
            raise ConnectionError("down")

    monkeypatch.setitem(sys.modules, "ollama", types.SimpleNamespace(Client=Boom))
    with pytest.raises(LLMError):
        OllamaClient("m").chat_json("s", "u", SCHEMA, 5)


def test_caching_client_replays_without_calling_inner(tmp_path):
    inner = FakeLLM(lambda *_: '{"indicators": []}')
    cache = CachingClient(inner, tmp_path)
    assert cache.chat_json("s", "u", SCHEMA, 10) == cache.chat_json("s", "u", SCHEMA, 10)
    assert len(inner.calls) == 1 and (cache.hits, cache.misses) == (1, 1)
    cache.chat_json("s", "other", SCHEMA, 10)
    assert len(inner.calls) == 2
    assert cache.info().model == "fake-1"


def test_build_client_validates_provider():
    with pytest.raises(ValueError, match="LLM_BASE_URL"):
        build_client("openai_compat", "m")
    with pytest.raises(ValueError, match="unknown"):
        build_client("nope", "m")
    assert (
        build_client("openai_compat", "m", base_url="http://x/v1").info().provider
        == "openai_compat"
    )
