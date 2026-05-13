# Source this file in the shell that runs LILO for initial GPT-3.5 Turbo trials.
#
# It maps retired or paper-era LILO model names to current gpt-3.5-turbo before
# LILO decides which OpenAI-compatible endpoint to call.

export LILO_LLM_MODEL_MAP='{"code-davinci-002":"gpt-3.5-turbo","gpt-3.5-turbo-0301":"gpt-3.5-turbo","gpt-4":"gpt-3.5-turbo","gpt-4-0314":"gpt-3.5-turbo"}'
export LILO_ENGINE_MAX_TOKENS="${LILO_ENGINE_MAX_TOKENS:-4096}"
