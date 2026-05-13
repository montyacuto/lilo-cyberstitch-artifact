"""
Compatibility helpers for the legacy OpenAI SDK used by LILO and newer SDKs.

The original code was written against openai<1.0. This module keeps the
call-sites small while allowing debug/cached runs to import without OpenAI
installed and live runs to fail with a clear setup error.
"""

import math
import os
import json
import re
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

try:
    from importlib import metadata as importlib_metadata
except ImportError:
    try:
        import importlib_metadata  # type: ignore
    except ModuleNotFoundError:
        importlib_metadata = None

try:
    import openai as _openai
except ModuleNotFoundError:
    _openai = None


class MissingOpenAIError(RuntimeError):
    pass


class LLMCacheError(RuntimeError):
    pass


class LLMCacheMissError(LLMCacheError):
    pass


if _openai is None:
    APIError = MissingOpenAIError
    APIConnectionError = MissingOpenAIError
    InvalidRequestError = MissingOpenAIError
    RateLimitError = MissingOpenAIError
    ServiceUnavailableError = MissingOpenAIError
    OpenAI = None
else:
    try:
        from openai.error import (  # type: ignore
            APIConnectionError,
            APIError,
            InvalidRequestError,
            RateLimitError,
            ServiceUnavailableError,
        )
    except Exception:
        APIError = getattr(_openai, "APIError", Exception)
        APIConnectionError = getattr(_openai, "APIConnectionError", APIError)
        InvalidRequestError = getattr(_openai, "BadRequestError", APIError)
        RateLimitError = getattr(_openai, "RateLimitError", APIError)
        ServiceUnavailableError = getattr(_openai, "InternalServerError", APIError)

    try:
        from openai import OpenAI  # type: ignore
    except Exception:
        OpenAI = None


class CompletionResult(dict):
    """Dict-compatible completion object with the legacy serializer method."""

    def to_dict_recursive(self):
        return to_plain_data(self)


def _openai_major_version():
    try:
        if importlib_metadata is None:
            return None
        return int(importlib_metadata.version("openai").split(".", 1)[0])
    except Exception:
        return None


def is_legacy_sdk():
    major = _openai_major_version()
    return major is not None and major < 1


def get_api_base():
    return (
        os.getenv("LILO_OPENAI_API_BASE")
        or os.getenv("OPENAI_API_BASE")
        or os.getenv("OPENAI_BASE_URL")
    )


def configure_api_key(api_key=None):
    if _openai is not None and is_legacy_sdk():
        _openai.api_key = api_key or os.getenv("OPENAI_API_KEY")
        api_base = get_api_base()
        if api_base:
            _openai.api_base = api_base


def require_openai_api_key(api_key=None):
    api_key = api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise MissingOpenAIError(
            "OPENAI_API_KEY is not set. Set it for live OpenAI queries, or run with debug/cache mode."
        )
    return api_key


def to_plain_data(value):
    if isinstance(value, CompletionResult):
        value = dict(value)
    elif hasattr(value, "to_dict_recursive"):
        return value.to_dict_recursive()
    elif hasattr(value, "model_dump"):
        return value.model_dump()

    if isinstance(value, dict):
        return {k: to_plain_data(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_plain_data(v) for v in value]
    return value


def completion_from_dict(data):
    return CompletionResult(to_plain_data(data))


def completion_to_dict(completion):
    return to_plain_data(completion)


def is_completion_response(value):
    data = to_plain_data(value)
    return isinstance(data, dict) and isinstance(data.get("choices"), list)


def normalize_completion_response(response):
    data = to_plain_data(response)
    if not isinstance(data, dict):
        raise TypeError(f"Unexpected OpenAI response type: {type(response)}")

    for choice in data.get("choices", []):
        if "text" not in choice and "message" in choice:
            content = choice["message"].get("content", "")
            if isinstance(content, list):
                content = "".join(
                    part.get("text", "") if isinstance(part, dict) else str(part)
                    for part in content
                )
            choice["text"] = content or ""
    return CompletionResult(data)


def _without_none(kwargs: Dict[str, Any]):
    return {k: v for k, v in kwargs.items() if v is not None}


def _model_env_name(model):
    safe_model = re.sub(r"[^A-Za-z0-9]+", "_", model).strip("_").upper()
    return f"LILO_LLM_{safe_model}_MODEL"


def resolve_model_alias(model):
    env_override = os.getenv(_model_env_name(model))
    if env_override:
        return env_override

    model_map_json = os.getenv("LILO_LLM_MODEL_MAP")
    if model_map_json:
        try:
            model_map = json.loads(model_map_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid LILO_LLM_MODEL_MAP JSON: {e}") from e
        return model_map.get(model, model)

    return model


def _cache_mode():
    mode = os.getenv("LILO_LLM_CACHE_MODE", "off").strip().lower()
    if mode in ("", "off", "none", "disabled"):
        return "off"
    if mode not in ("record", "replay"):
        raise LLMCacheError(
            "Invalid LILO_LLM_CACHE_MODE={!r}; expected off, record, or replay.".format(
                mode
            )
        )
    return mode


def _cache_dir():
    cache_dir = os.getenv("LILO_LLM_CACHE_DIR")
    if not cache_dir:
        raise LLMCacheError(
            "LILO_LLM_CACHE_DIR is required when LILO_LLM_CACHE_MODE is record or replay."
        )
    return Path(cache_dir)


def _now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _canonical_json(data):
    return json.dumps(
        to_plain_data(data), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _request_hash(request):
    return hashlib.sha256(_canonical_json(request).encode("utf-8")).hexdigest()


def _cache_path(kind, request_hash):
    return _cache_dir() / kind / "{}.json".format(request_hash)


def _without_derived_request_fields(request):
    request = to_plain_data(request)
    if not isinstance(request, dict):
        return request
    request = dict(request)
    request.pop("max_tokens", None)
    return request


def _load_compatible_completion_response(request):
    request_identity = _canonical_json(_without_derived_request_fields(request))
    matches = []
    completion_dir = _cache_dir() / "completion"
    if not completion_dir.exists():
        return None, None
    for path in completion_dir.glob("*.json"):
        try:
            with path.open("r") as f:
                entry = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        cached_request = entry.get("request")
        if (
            _canonical_json(_without_derived_request_fields(cached_request))
            == request_identity
        ):
            matches.append((entry, path))

    if not matches:
        return None, None
    if len(matches) > 1:
        raise LLMCacheError(
            "Ambiguous replay cache hits for completion request {} after ignoring derived max_tokens.".format(
                _request_hash(request)
            )
        )

    entry, path = matches[0]
    print(
        "LILO LLM cache compatible hit: completion {} (current request {}; max_tokens ignored)".format(
            entry.get("request_hash"), _request_hash(request)
        )
    )
    return entry["response"], entry.get("request_hash")


def _load_cached_response(kind, request):
    mode = _cache_mode()
    if mode == "off":
        return None, None

    request_hash = _request_hash(request)
    path = _cache_path(kind, request_hash)
    if path.exists():
        with path.open("r") as f:
            entry = json.load(f)
        if entry.get("request_hash") != request_hash:
            raise LLMCacheError("Cache entry hash mismatch: {}".format(path))
        if _canonical_json(entry.get("request")) != _canonical_json(request):
            raise LLMCacheError("Cache entry request mismatch: {}".format(path))
        print("LILO LLM cache hit: {} {}".format(kind, request_hash))
        return entry["response"], request_hash

    if mode == "replay":
        if kind == "completion":
            cached_response, compatible_hash = _load_compatible_completion_response(
                request
            )
            if cached_response is not None:
                return cached_response, compatible_hash

        miss_path = _cache_dir() / "misses" / "{}.json".format(request_hash)
        miss_path.parent.mkdir(parents=True, exist_ok=True)
        with miss_path.open("w") as f:
            json.dump(
                {
                    "cache_version": 1,
                    "kind": kind,
                    "request_hash": request_hash,
                    "created_at": _now_iso(),
                    "request": to_plain_data(request),
                    "expected_path": str(path),
                },
                f,
                indent=2,
                sort_keys=True,
            )
        raise LLMCacheMissError(
            "LILO LLM replay cache miss for {} request {}. Cache file expected at: {}. Miss diagnostic: {}".format(
                kind, request_hash, path, miss_path
            )
        )

    return None, request_hash


def _write_cached_response(kind, request, request_hash, response):
    if _cache_mode() != "record":
        return
    if not request_hash:
        request_hash = _request_hash(request)

    cache_root = _cache_dir()
    path = _cache_path(kind, request_hash)
    if path.exists():
        return

    response_data = to_plain_data(response)
    entry = {
        "cache_version": 1,
        "kind": kind,
        "request_hash": request_hash,
        "created_at": _now_iso(),
        "request": to_plain_data(request),
        "response": response_data,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".json.tmp")
    with tmp_path.open("w") as f:
        json.dump(entry, f, indent=2, sort_keys=True)
    os.replace(str(tmp_path), str(path))

    summary = {
        "created_at": entry["created_at"],
        "kind": kind,
        "request_hash": request_hash,
        "path": str(path),
        "requested_model": request.get("requested_model"),
        "resolved_model": request.get("resolved_model"),
        "response_model": response_data.get("model")
        if isinstance(response_data, dict)
        else None,
        "usage": response_data.get("usage") if isinstance(response_data, dict) else None,
    }
    with (cache_root / "manifest.jsonl").open("a") as f:
        f.write(_canonical_json(summary) + "\n")
    print("LILO LLM cache wrote: {} {}".format(kind, request_hash))


def _completion_cache_request(
    *,
    requested_model,
    resolved_model,
    prompt,
    messages,
    is_chat,
    temperature,
    top_p,
    n,
    stop,
    max_tokens,
    logprobs,
    best_of,
):
    return {
        "kind": "completion",
        "requested_model": requested_model,
        "resolved_model": resolved_model,
        "is_chat": is_chat,
        "prompt": prompt,
        "messages": messages,
        "temperature": temperature,
        "top_p": top_p,
        "n": n,
        "stop": stop,
        "max_tokens": max_tokens,
        "logprobs": logprobs,
        "best_of": best_of,
    }


def _embedding_cache_request(*, requested_model, resolved_model, input_text):
    return {
        "kind": "embedding",
        "requested_model": requested_model,
        "resolved_model": resolved_model,
        "input": input_text,
    }


def _embedding_from_response(response):
    data = to_plain_data(response)
    return data["data"][0]["embedding"]


def create_completion(
    *,
    model,
    prompt,
    messages,
    is_chat,
    temperature,
    top_p,
    n,
    stop,
    max_tokens,
    logprobs=None,
    best_of=1,
    api_key=None,
):
    requested_model = model
    model = resolve_model_alias(model)
    cache_request = _completion_cache_request(
        requested_model=requested_model,
        resolved_model=model,
        prompt=prompt,
        messages=messages,
        is_chat=is_chat,
        temperature=temperature,
        top_p=top_p,
        n=n,
        stop=stop,
        max_tokens=max_tokens,
        logprobs=logprobs,
        best_of=best_of,
    )
    cached_response, request_hash = _load_cached_response("completion", cache_request)
    if cached_response is not None:
        return normalize_completion_response(cached_response)

    api_key = require_openai_api_key(api_key)
    if _openai is None:
        raise MissingOpenAIError(
            "The openai package is not installed in this Python environment."
        )

    if is_legacy_sdk():
        configure_api_key(api_key)
        if is_chat:
            response = _openai.ChatCompletion.create(
                **_without_none(
                    dict(
                        model=model,
                        messages=messages,
                        temperature=temperature,
                        top_p=top_p,
                        n=n,
                        stop=stop,
                        max_tokens=max_tokens,
                    )
                )
            )
        else:
            response = _openai.Completion.create(
                **_without_none(
                    dict(
                        model=model,
                        prompt=prompt,
                        temperature=temperature,
                        top_p=top_p,
                        n=n,
                        stop=stop,
                        max_tokens=max_tokens,
                        logprobs=logprobs,
                        best_of=best_of,
                    )
                )
            )
    else:
        if OpenAI is None:
            raise MissingOpenAIError(
                "The installed openai package does not expose the OpenAI client."
            )
        client_kwargs = {"api_key": api_key}
        api_base = get_api_base()
        if api_base:
            client_kwargs["base_url"] = api_base
        client = OpenAI(**client_kwargs)
        if is_chat:
            response = client.chat.completions.create(
                **_without_none(
                    dict(
                        model=model,
                        messages=messages,
                        temperature=temperature,
                        top_p=top_p,
                        n=n,
                        stop=stop,
                        max_tokens=max_tokens,
                    )
                )
            )
        else:
            response = client.completions.create(
                **_without_none(
                    dict(
                        model=model,
                        prompt=prompt,
                        temperature=temperature,
                        top_p=top_p,
                        n=n,
                        stop=stop,
                        max_tokens=max_tokens,
                        logprobs=logprobs,
                        best_of=best_of,
                    )
                )
            )

    normalized_response = normalize_completion_response(response)
    _write_cached_response(
        "completion", cache_request, request_hash, completion_to_dict(normalized_response)
    )
    return normalized_response


def get_embedding(text, engine=None, model=None, api_key=None):
    requested_model = model or engine
    if not requested_model:
        raise ValueError("Embedding model is required.")
    model = resolve_model_alias(requested_model)
    input_text = text.replace("\n", " ")
    cache_request = _embedding_cache_request(
        requested_model=requested_model, resolved_model=model, input_text=input_text
    )
    cached_response, request_hash = _load_cached_response("embedding", cache_request)
    if cached_response is not None:
        return _embedding_from_response(cached_response)

    api_key = require_openai_api_key(api_key)
    if _openai is None:
        raise MissingOpenAIError(
            "The openai package is not installed in this Python environment."
        )

    if is_legacy_sdk():
        configure_api_key(api_key)
        response = _openai.Embedding.create(input=[input_text], model=model)
        data = to_plain_data(response)
        _write_cached_response("embedding", cache_request, request_hash, data)
        return _embedding_from_response(data)

    if OpenAI is None:
        raise MissingOpenAIError(
            "The installed openai package does not expose the OpenAI client."
        )
    client_kwargs = {"api_key": api_key}
    api_base = get_api_base()
    if api_base:
        client_kwargs["base_url"] = api_base
    response = OpenAI(**client_kwargs).embeddings.create(model=model, input=[input_text])
    data = to_plain_data(response)
    _write_cached_response("embedding", cache_request, request_hash, data)
    return _embedding_from_response(data)


def cosine_similarity(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
