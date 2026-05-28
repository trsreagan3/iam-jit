"""
SD-2 POSITIVE fixture: parameters declared but never used — SHOULD flag.
"""


# Case 1: plain unused param
def case1_unused_param(x: str, y: int) -> str:
    return "hello"  # y is never used


# Case 2: keyword-only unused param
def case2_keyword_only(*, name: str, extra: str) -> str:
    return name  # extra never used


# Case 3: multiple params, one unused
def case3_partial_use(a: int, b: int, c: int) -> int:
    return a + b  # c never used
