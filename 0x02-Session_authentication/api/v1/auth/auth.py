#!/usr/bin/env python3
"""
Auth Class
"""
import os
from flask import request
from typing import (
    List,
    TypeVar
)


class Auth:
    """
    Authentication
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        requie auth
        """
        if path is None:
            return True
        elif excluded_paths is None or excluded_paths == []:
            return True
        elif path in excluded_paths:
            return False
        else:
            for i in excluded_paths:
                if i.startswith(path):
                    return False
                if path.startswith(i):
                    return False
                if i[-1] == "*":
                    if path.startswith(i[:-1]):
                        return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        return auth header
        """
        if request is None:
            return None
        header = request.headers.get('Authorization')
        if header is None:
            return None
        return header

    def current_user(self, request=None) -> TypeVar('User'):
        """
        return user instance
        """
        return None

    def session_cookie(self, request=None):
        """
        session cookies
        """
        if request is None:
            return None
        session = os.getenv('SESSION_NAME')
        return request.cookies.get(session)
