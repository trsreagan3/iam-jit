"""
SD-1 NEGATIVE fixture: these patterns should NOT be flagged.
"""
import logging
logger = logging.getLogger(__name__)


# Case 1: except with log — should NOT flag
def case1_except_with_log():
    try:
        risky()
    except Exception as e:
        logger.warning("caught: %s", e)


# Case 2: except with re-raise — should NOT flag
def case2_except_reraise():
    try:
        risky()
    except ValueError as e:
        raise RuntimeError("wrapped") from e


# Case 3: except with meaningful body — should NOT flag
def case3_except_with_body():
    result = None
    try:
        result = risky()
    except Exception:
        result = "default"
    return result


# Case 4: noqa suppression — should NOT flag
def case4_noqa():
    try:
        risky()
    except Exception:  # noqa: SD-1 intentional: optional cleanup step
        pass


def risky():
    raise RuntimeError("oops")
