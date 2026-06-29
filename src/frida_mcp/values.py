from __future__ import annotations


def preview_of(value: dict) -> str:
    if "preview" in value:
        return str(value["preview"])
    kind = value.get("type")
    if kind == "string":
        return '"' + str(value.get("value", "")) + '"'
    if kind in ("number", "boolean"):
        return str(value.get("value"))
    if kind == "null":
        return "null"
    return f"[{kind}]"


def is_pointer(value: dict) -> bool:
    return value.get("type") == "pointer"


def pointer_address(value: dict) -> str | None:
    return value.get("value") if is_pointer(value) else None
