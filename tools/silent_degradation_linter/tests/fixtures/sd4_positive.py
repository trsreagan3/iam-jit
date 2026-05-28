"""
SD-4 POSITIVE fixture: positive return inside except block — SHOULD flag.
"""


# Case 1: return True inside except
def case1_return_true():
    try:
        do_thing()
    except Exception:
        return True  # SD-4: caller can't detect failure


# Case 2: return None inside except (bare return)
def case2_bare_return():
    try:
        do_thing()
    except ValueError:
        return  # SD-4: implicit None, caller can't tell it failed


# Case 3: return dict with status ok
def case3_return_status_ok():
    try:
        do_thing()
    except Exception:
        return {"status": "ok"}  # SD-4: positive shape on failure


# Case 4: return "success" string
def case4_return_success_str():
    try:
        do_thing()
    except RuntimeError:
        return "ok"  # SD-4: positive string on failure


def do_thing():
    raise RuntimeError("fail")
