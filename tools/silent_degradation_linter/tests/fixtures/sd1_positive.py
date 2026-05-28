"""
SD-1 POSITIVE fixture: these patterns SHOULD be flagged.
"""

# Case 1: bare except with pass
def case1_bare_except():
    try:
        risky()
    except:
        pass


# Case 2: except Exception: pass
def case2_except_exception():
    try:
        risky()
    except Exception:
        pass


# Case 3: except specific type: pass
def case3_except_valueerror():
    try:
        risky()
    except ValueError:
        pass


# Case 4: except tuple: pass
def case4_except_tuple():
    try:
        risky()
    except (TypeError, ValueError):
        pass


def risky():
    raise RuntimeError("oops")
