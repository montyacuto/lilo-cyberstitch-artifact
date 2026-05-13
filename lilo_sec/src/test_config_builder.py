from src.config_builder import build_config
from src.models.laps_dreamcoder_recognition import LAPSDreamCoderRecognition
from src.models.laps_grammar import LAPSGrammar
from src.models.model_loaders import AMORTIZED_SYNTHESIS


def _enumeration_blocks(config):
    return [
        block
        for block in config["experiment_iterator"]["loop_blocks"]
        if (
            block.get("model_type") == LAPSGrammar.GRAMMAR
            and block.get("model_fn") == LAPSGrammar.infer_programs_for_tasks.__name__
        )
        or (
            block.get("model_type") == AMORTIZED_SYNTHESIS
            and block.get("model_fn")
            == LAPSDreamCoderRecognition.infer_programs_for_tasks.__name__
        )
    ]


def test_build_config_injects_max_mem_per_enumeration_thread():
    config = build_config(
        experiment_name="test_logo_2gb_cap",
        experiment_type="lilo_original_completion",
        domain="logo",
        encoder="LOGO",
        global_batch_size=96,
        max_mem_per_enumeration_thread=2000000000,
        s3_sync=False,
    )

    blocks = _enumeration_blocks(config)
    assert blocks
    assert all(
        block["params"]["max_mem_per_enumeration_thread"] == 2000000000
        for block in blocks
    )
    assert (
        config["metadata"]["max_mem_per_enumeration_thread"] == 2000000000
    )


def test_build_config_leaves_max_mem_per_enumeration_thread_unset_by_default():
    config = build_config(
        experiment_name="test_logo_default_cap",
        experiment_type="lilo_original_completion",
        domain="logo",
        encoder="LOGO",
        global_batch_size=96,
        s3_sync=False,
    )

    blocks = _enumeration_blocks(config)
    assert blocks
    assert all(
        "max_mem_per_enumeration_thread" not in block["params"]
        for block in blocks
    )
    assert config["metadata"]["max_mem_per_enumeration_thread"] is None
