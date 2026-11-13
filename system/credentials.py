"""Windows Credential Manager access through keyring."""

from __future__ import annotations

from typing import Protocol

from app.constants import KEYRING_SERVICE


class KeyringBackend(Protocol):
    def get_password(self, service_name: str, username: str) -> str | None: ...

    def set_password(self, service_name: str, username: str, password: str) -> None: ...

    def delete_password(self, service_name: str, username: str) -> None: ...


class CredentialStoreError(RuntimeError):
    """A sanitized credential operation failure."""


class CredentialStore:
    """Store only the password in the operating-system credential vault."""

    def __init__(self, backend: KeyringBackend | None = None) -> None:
        self._backend = backend

    def _get_backend(self) -> KeyringBackend:
        if self._backend is None:
            try:
                import keyring
            except ImportError:
                raise CredentialStoreError("keyring 依赖尚未安装") from None
            self._backend = keyring
        return self._backend

    def get(self, username: str) -> str | None:
        if not username:
            return None
        try:
            return self._get_backend().get_password(KEYRING_SERVICE, username)
        except Exception:
            raise CredentialStoreError("无法读取 Windows 凭据") from None

    def set(self, username: str, password: str) -> None:
        if not username:
            raise CredentialStoreError("保存密码前必须填写账号")
        try:
            self._get_backend().set_password(KEYRING_SERVICE, username, password)
        except Exception:
            raise CredentialStoreError("无法写入 Windows 凭据") from None

    def delete(self, username: str) -> None:
        if not username:
            return
        try:
            self._get_backend().delete_password(KEYRING_SERVICE, username)
        except Exception:
            # A missing credential and an unavailable backend are both safe here.
            return

