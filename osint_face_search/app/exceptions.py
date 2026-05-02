"""Domain-specific istisnalar."""
from fastapi import HTTPException, status


class CaseNotFound(HTTPException):
    def __init__(self, case_id: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vaka bulunamadı: {case_id}",
        )


class InvalidImage(HTTPException):
    def __init__(self, detail: str = "Geçersiz görüntü"):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class CaseClosed(HTTPException):
    def __init__(self, case_id: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Vaka kapalı, sorgu yapılamaz: {case_id}",
        )
