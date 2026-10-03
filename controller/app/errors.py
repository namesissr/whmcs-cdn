"""ApiError: an error answered with a flat JSON body, e.g. 409 {"detail": "invalid_state", "state": "running"}
(SPEC §23 shapes). Registered as an exception handler in main.py."""


class ApiError(Exception):
    def __init__(self, status: int, detail: str, **extra):
        super().__init__(detail)
        self.status = status
        self.body = {"detail": detail, **extra}
