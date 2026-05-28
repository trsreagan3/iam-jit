"""
SD-2 NEGATIVE fixture: these patterns should NOT be flagged.
"""
from typing import Protocol


# Case 1: all params used — should NOT flag
def case1_all_used(x: str, y: int) -> str:
    return f"{x}-{y}"


# Case 2: underscore prefix opt-out — should NOT flag
def case2_underscore_prefix(_unused: str, name: str) -> str:
    return name


# Case 3: self / cls — should NOT flag
class Foo:
    def case3_self_cls(self, value: str) -> str:
        return value


# Case 4: stub function (ellipsis body) — should NOT flag
class StoreProtocol(Protocol):
    def get(self, item_id: str) -> dict: ...
    def put(self, item: dict) -> None: ...


# Case 5: abstract method — should NOT flag
from abc import abstractmethod, ABC

class Base(ABC):
    @abstractmethod
    def process(self, data: bytes) -> str:
        ...


# Case 6: noqa suppression — should NOT flag
def case6_noqa(unused_but_allowed: str) -> None:  # noqa: SD-2 legacy API compat
    return None


# Case 7: param used in nested function — should NOT flag
def case7_nested(value: str) -> callable:
    def inner():
        return value  # uses outer param
    return inner


# Case 8: pass-body stub — should NOT flag
def case8_pass_stub(x: str) -> None:
    pass
