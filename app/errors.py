"""统一的 API 错误类型。"""
from __future__ import annotations


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def invalid_pem(message: str) -> ApiError:
    return ApiError(400, "invalid_pem", message)


def invalid_window(message: str) -> ApiError:
    return ApiError(422, "invalid_time_window", message)


def not_found(code: str, message: str) -> ApiError:
    return ApiError(404, code, message)


def conflict(code: str, message: str) -> ApiError:
    return ApiError(409, code, message)
