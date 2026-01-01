#!/usr/bin/env python3
"""
Custom exception handlers for the server.
"""

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse


class ServerException(Exception):
    """Base exception for server errors"""

    def __init__(self, message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class AuthenticationError(ServerException):
    """Authentication failed"""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED)


class AuthorizationError(ServerException):
    """Authorization failed"""

    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message, status.HTTP_403_FORBIDDEN)


class ResourceNotFoundError(ServerException):
    """Resource not found"""

    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, status.HTTP_404_NOT_FOUND)


class ValidationError(ServerException):
    """Validation failed"""

    def __init__(self, message: str = "Validation failed"):
        super().__init__(message, status.HTTP_400_BAD_REQUEST)


async def server_exception_handler(request: Request, exc: ServerException):
    """Handle ServerException and its subclasses"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message, "success": False},
    )


async def generic_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "success": False,
        },
    )
