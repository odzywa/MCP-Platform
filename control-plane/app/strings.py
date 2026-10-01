"""String/slug/identifier helpers shared across the control-plane."""
import re

from fastapi import HTTPException


def slug(value: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9-]+", "-", value.strip().lower()).strip("-")
    return clean or "runtime"


def clean_words(value: str, pattern: str, field: str) -> list[str]:
    words = [item.strip() for item in re.split(r"[\s,]+", value or "") if item.strip()]
    invalid = [item for item in words if not re.fullmatch(pattern, item)]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid {field}: {', '.join(invalid[:5])}")
    return words


def validate_image_ref(value: str, field: str = "image") -> str:
    image = value.strip()
    if not image or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,180}", image):
        raise HTTPException(status_code=400, detail=f"Invalid {field}")
    return image
