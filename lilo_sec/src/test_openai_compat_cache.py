import json

import pytest

from src import openai_compat


def _write_cache_entry(cache_dir, kind, request, response):
    request_hash = openai_compat._request_hash(request)
    path = cache_dir / kind / "{}.json".format(request_hash)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(
            {
                "cache_version": 1,
                "kind": kind,
                "request_hash": request_hash,
                "created_at": "2026-05-06T00:00:00Z",
                "request": request,
                "response": response,
            },
            f,
        )
    return path


def test_completion_replay_does_not_require_api_key(tmp_path, monkeypatch):
    monkeypatch.setenv("LILO_LLM_CACHE_MODE", "replay")
    monkeypatch.setenv("LILO_LLM_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    request = openai_compat._completion_cache_request(
        requested_model="gpt-3.5-turbo",
        resolved_model="gpt-3.5-turbo",
        prompt=None,
        messages=[{"role": "user", "content": "hello"}],
        is_chat=True,
        temperature=0.9,
        top_p=None,
        n=1,
        stop="\n",
        max_tokens=16,
        logprobs=None,
        best_of=1,
    )
    _write_cache_entry(
        tmp_path,
        "completion",
        request,
        {
            "id": "cached",
            "object": "chat.completion",
            "model": "gpt-3.5-turbo-0125",
            "choices": [{"index": 0, "message": {"content": "cached answer"}}],
        },
    )

    completion = openai_compat.create_completion(
        model="gpt-3.5-turbo",
        prompt=None,
        messages=[{"role": "user", "content": "hello"}],
        is_chat=True,
        temperature=0.9,
        top_p=None,
        n=1,
        stop="\n",
        max_tokens=16,
    )

    assert completion["choices"][0]["text"] == "cached answer"


def test_completion_replay_fails_closed_on_cache_miss(tmp_path, monkeypatch):
    monkeypatch.setenv("LILO_LLM_CACHE_MODE", "replay")
    monkeypatch.setenv("LILO_LLM_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(openai_compat.LLMCacheMissError):
        openai_compat.create_completion(
            model="gpt-3.5-turbo",
            prompt=None,
            messages=[{"role": "user", "content": "uncached"}],
            is_chat=True,
            temperature=0.9,
            top_p=None,
            n=1,
            stop="\n",
            max_tokens=16,
        )


def test_completion_replay_allows_derived_max_tokens_difference(tmp_path, monkeypatch):
    monkeypatch.setenv("LILO_LLM_CACHE_MODE", "replay")
    monkeypatch.setenv("LILO_LLM_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    cached_request = openai_compat._completion_cache_request(
        requested_model="gpt-3.5-turbo",
        resolved_model="gpt-3.5-turbo",
        prompt=None,
        messages=[{"role": "user", "content": "same prompt"}],
        is_chat=True,
        temperature=0.9,
        top_p=None,
        n=1,
        stop="\n",
        max_tokens=144,
        logprobs=None,
        best_of=1,
    )
    _write_cache_entry(
        tmp_path,
        "completion",
        cached_request,
        {
            "id": "cached",
            "object": "chat.completion",
            "model": "gpt-3.5-turbo-0125",
            "choices": [{"index": 0, "message": {"content": "compatible answer"}}],
        },
    )

    completion = openai_compat.create_completion(
        model="gpt-3.5-turbo",
        prompt=None,
        messages=[{"role": "user", "content": "same prompt"}],
        is_chat=True,
        temperature=0.9,
        top_p=None,
        n=1,
        stop="\n",
        max_tokens=92,
    )

    assert completion["choices"][0]["text"] == "compatible answer"


def test_embedding_replay_does_not_require_api_key(tmp_path, monkeypatch):
    monkeypatch.setenv("LILO_LLM_CACHE_MODE", "replay")
    monkeypatch.setenv("LILO_LLM_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    request = openai_compat._embedding_cache_request(
        requested_model="text-embedding-ada-002",
        resolved_model="text-embedding-3-small",
        input_text="hello world",
    )
    _write_cache_entry(
        tmp_path,
        "embedding",
        request,
        {
            "object": "list",
            "model": "text-embedding-3-small",
            "data": [{"object": "embedding", "embedding": [0.1, 0.2, 0.3]}],
        },
    )

    monkeypatch.setenv(
        "LILO_LLM_MODEL_MAP",
        json.dumps({"text-embedding-ada-002": "text-embedding-3-small"}),
    )

    assert openai_compat.get_embedding("hello\nworld", engine="text-embedding-ada-002") == [
        0.1,
        0.2,
        0.3,
    ]


def test_cache_key_excludes_api_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-api-key")
    request = openai_compat._completion_cache_request(
        requested_model="gpt-3.5-turbo",
        resolved_model="gpt-3.5-turbo",
        prompt=None,
        messages=[{"role": "user", "content": "hello"}],
        is_chat=True,
        temperature=0.9,
        top_p=None,
        n=1,
        stop="\n",
        max_tokens=16,
        logprobs=None,
        best_of=1,
    )

    serialized = openai_compat._canonical_json(request)
    assert "test-openai-api-key" not in serialized


def test_record_write_creates_manifest_without_api_key(tmp_path, monkeypatch):
    monkeypatch.setenv("LILO_LLM_CACHE_MODE", "record")
    monkeypatch.setenv("LILO_LLM_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-api-key")

    request = openai_compat._completion_cache_request(
        requested_model="gpt-3.5-turbo",
        resolved_model="gpt-3.5-turbo",
        prompt=None,
        messages=[{"role": "user", "content": "hello"}],
        is_chat=True,
        temperature=0.9,
        top_p=None,
        n=1,
        stop="\n",
        max_tokens=16,
        logprobs=None,
        best_of=1,
    )
    request_hash = openai_compat._request_hash(request)
    openai_compat._write_cached_response(
        "completion",
        request,
        request_hash,
        {"model": "gpt-3.5-turbo-0125", "choices": [{"text": "cached"}]},
    )

    cache_text = (tmp_path / "completion" / "{}.json".format(request_hash)).read_text()
    manifest_text = (tmp_path / "manifest.jsonl").read_text()
    assert "test-openai-api-key" not in cache_text
    assert "test-openai-api-key" not in manifest_text
