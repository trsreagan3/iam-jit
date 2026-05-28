"""
SD-4 NEGATIVE fixture: these patterns should NOT be flagged.
"""


# Case 1: return error/failure shape inside except — NOT flagged
def case1_return_error():
    try:
        do_thing()
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# Case 2: return False inside except — NOT flagged
def case2_return_false():
    try:
        do_thing()
    except Exception:
        return False


# Case 3: raise inside except — NOT flagged (no return at all)
def case3_reraise():
    try:
        do_thing()
    except Exception as e:
        raise RuntimeError("wrapped") from e


# Case 4: positive return OUTSIDE except — NOT flagged
def case4_positive_outside():
    try:
        do_thing()
    except Exception as e:
        raise
    return True  # this is outside the except block, fine


# Case 5: return {"status": "ok"} with noqa suppression — NOT flagged
def case5_noqa():
    try:
        do_thing()
    except Exception:
        return {"status": "ok"}  # noqa: SD-4 optional probe, caller checks separately


# Case 6: return string error message — NOT flagged
def case6_return_error_str():
    try:
        do_thing()
    except Exception as e:
        return str(e)


def do_thing():
    raise RuntimeError("fail")
