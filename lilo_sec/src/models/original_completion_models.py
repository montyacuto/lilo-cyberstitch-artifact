"""
Original-style OpenAI completion model loaders.

This module is a parallel path for running current instruct completion models
through the legacy OpenAI completion API, without the local OpenAI compatibility
wrapper, chat conversion, model aliasing, or LLM cache layer used by the main
`gpt_solver` / `gpt_library_namer` pipeline.
"""

import os
import re
import time
import warnings
from typing import Union

import openai
from openai.error import (
    APIConnectionError,
    APIError,
    InvalidRequestError,
    RateLimitError,
    ServiceUnavailableError,
)

try:
    from transformers import GPT2TokenizerFast
except ModuleNotFoundError:
    GPT2TokenizerFast = None

import src.models.model_loaders as model_loaders
from src.models.gpt_base import BasePrompt, DEFAULT_LINE_SEPARATOR, Prompt
from src.models.gpt_solver import GPTSolver
from src.models.library_namer import GPTLibraryNamer

LLMSolverRegistry = model_loaders.ModelLoaderRegistries[model_loaders.LLM_SOLVER]
LibraryNamerRegistry = model_loaders.ModelLoaderRegistries[
    model_loaders.LIBRARY_NAMER
]


class OriginalOpenAICompletionMixin:
    """Legacy `openai.Completion.create` behavior for completion models."""

    ENGINE_CODEX = "code-davinci-002"
    ENGINE_GPT_3_5_TURBO_INSTRUCT = "gpt-3.5-turbo-instruct"
    ENGINE_DEFAULT = ENGINE_GPT_3_5_TURBO_INSTRUCT
    ENGINE_MAX_TOKENS_FALLBACK = 4096
    RATE_LIMIT_MIN_SLEEP_SECONDS = 1.0
    RATE_LIMIT_RETRY_BUFFER_SECONDS = 1.0
    RATE_LIMIT_MAX_SLEEP_SECONDS = 300.0
    RATE_LIMIT_RETRY_RE = re.compile(
        r"(?:try again|retry)\s+in\s+([0-9]+(?:\.[0-9]+)?)\s*(ms|milliseconds?|s|sec|secs|seconds?)",
        re.IGNORECASE,
    )

    # Max tokens for BOTH the prompt and the completion.
    MAX_TOKENS_PER_ENGINE = {
        ENGINE_CODEX: 4096,
        ENGINE_GPT_3_5_TURBO_INSTRUCT: 4096,
    }

    def _init_original_openai_completion(self, engine=None):
        if not os.getenv("OPENAI_API_KEY"):
            raise ValueError(
                "OPENAI_API_KEY is not set. Please set this in the shell via `export OPENAI_API_KEY=...`"
            )
        openai.api_key = os.environ["OPENAI_API_KEY"]

        self.ENGINE = engine or self.ENGINE_DEFAULT
        self.ENGINE_MAX_TOKENS = self.MAX_TOKENS_PER_ENGINE.get(
            self.ENGINE,
            int(
                os.getenv(
                    "LILO_ORIGINAL_COMPLETION_ENGINE_MAX_TOKENS",
                    self.ENGINE_MAX_TOKENS_FALLBACK,
                )
            ),
        )

        self.tokenizer = None
        if GPT2TokenizerFast is not None:
            try:
                self.tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
                self.tokenizer.model_max_length = self.ENGINE_MAX_TOKENS
            except Exception as e:
                warnings.warn(
                    "Unable to load GPT-2 tokenizer; falling back to an approximate "
                    f"token counter. Original error: {type(e).__name__}: {e}"
                )
        else:
            warnings.warn(
                "transformers is not installed; falling back to an approximate token counter."
            )
        os.environ["TOKENIZERS_PARALLELISM"] = str(False)

    def _get_rate_limit_sleep_seconds(self, error, fallback_seconds):
        """Return a bounded retry delay from OpenAI's hint, if available."""

        retry_after = None
        headers = getattr(error, "headers", None) or {}
        if headers:
            retry_after = (
                headers.get("retry-after")
                or headers.get("Retry-After")
                or headers.get("retry_after")
            )
        if retry_after is not None:
            try:
                retry_after = float(retry_after)
            except (TypeError, ValueError):
                retry_after = None

        if retry_after is None:
            match = self.RATE_LIMIT_RETRY_RE.search(str(error))
            if match:
                retry_after = float(match.group(1))
                unit = match.group(2).lower()
                if unit.startswith("ms") or unit.startswith("millisecond"):
                    retry_after /= 1000.0

        if retry_after is None:
            retry_after = float(fallback_seconds)
        else:
            retry_after += self.RATE_LIMIT_RETRY_BUFFER_SECONDS

        return min(
            self.RATE_LIMIT_MAX_SLEEP_SECONDS,
            max(self.RATE_LIMIT_MIN_SLEEP_SECONDS, retry_after),
        )

    def query_completion(
        self,
        prompt: Union[Prompt, str],
        n_samples: int,
        best_of: int = 1,
        temperature: float = None,
        max_tokens: int = 256,
        stop: str = DEFAULT_LINE_SEPARATOR,
        line_separator: str = DEFAULT_LINE_SEPARATOR,
        top_p=None,
        logprobs=None,
        max_attempts_rate_limit=5,
        rate_limit_seconds=30,
    ):
        pause_for_rate_limit = False
        rate_limit_sleep_seconds = float(rate_limit_seconds)
        completion = None
        for idx in range(max_attempts_rate_limit):
            if pause_for_rate_limit:
                print(
                    f"ERR: OpenAI rate limit. On attempt {idx}/{max_attempts_rate_limit}; sleeping {rate_limit_sleep_seconds:.3f}s."
                )
                time.sleep(rate_limit_sleep_seconds)
                rate_limit_seconds *= 2
            try:
                completion = self._create_completion(
                    prompt=prompt,
                    temperature=temperature,
                    top_p=top_p,
                    n_samples=n_samples,
                    stop=stop,
                    best_of=best_of,
                    line_separator=line_separator,
                    max_tokens=max_tokens,
                    logprobs=logprobs,
                )
                return completion
            except InvalidRequestError as e:
                print(e)
                return e
            except (
                RateLimitError,
                APIConnectionError,
                APIError,
                ServiceUnavailableError,
            ) as e:
                print(e)
                pause_for_rate_limit = True
                rate_limit_sleep_seconds = self._get_rate_limit_sleep_seconds(
                    e, fallback_seconds=rate_limit_seconds
                )
                completion = e

        return completion

    def is_chat_format(self):
        return False

    def _create_completion(
        self,
        prompt,
        temperature,
        top_p,
        n_samples,
        best_of,
        stop,
        line_separator,
        max_tokens,
        logprobs,
    ):
        # Match the original LILO completion call shape: do not send `best_of`.
        return openai.Completion.create(
            model=self.ENGINE,
            prompt=str(prompt),
            temperature=temperature,
            top_p=top_p,
            n=n_samples,
            stop=stop,
            max_tokens=max_tokens,
            logprobs=logprobs,
        )

    def count_tokens_gpt2(self, text):
        if self.tokenizer is None:
            return max(1, int(len(str(text)) / 4))
        return len(self.tokenizer(text, truncation=False)["input_ids"])


@LLMSolverRegistry.register
class OriginalCompletionGPTSolver(OriginalOpenAICompletionMixin, GPTSolver):
    name = "original_completion_gpt_solver"

    @staticmethod
    def load_model(experiment_state, **kwargs):
        return OriginalCompletionGPTSolver(experiment_state=experiment_state, **kwargs)

    def __init__(self, experiment_state=None, engine=None):
        self._init_original_openai_completion(engine=engine)


@LibraryNamerRegistry.register
class OriginalCompletionGPTLibraryNamer(
    OriginalOpenAICompletionMixin, GPTLibraryNamer
):
    name = "original_completion_gpt_library_namer"

    @staticmethod
    def load_model(experiment_state, **kwargs):
        return OriginalCompletionGPTLibraryNamer(
            experiment_state=experiment_state, **kwargs
        )

    def __init__(self, experiment_state=None, engine=None):
        self._init_original_openai_completion(engine=engine)
