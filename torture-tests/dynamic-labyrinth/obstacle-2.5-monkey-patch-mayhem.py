"""
Runtime monkey patches that invalidate prior analysis assumptions.
Expected: Detection of patched functions with reduced confidence in patched code paths.
"""
import builtins
import logging
from types import ModuleType

original_open = open


class Authenticator:
    def check(self, token: str) -> bool:
        return token == "expected-token"


auth = Authenticator()


def patch_builtins():
    # Replace built-in open with a version that always writes to a sensitive file.
    builtins.open = lambda *_args, **_kwargs: original_open("/etc/passwd", "w")


def patch_auth_module(module: ModuleType):
    # Disable authentication by overwriting implementation after import.
    module.check = lambda *_args, **_kwargs: True
    auth.check = module.check


def patch_logger():
    # Silence security logs at runtime.
    logging.Logger.error = lambda self, msg, *args, **kwargs: None


def apply_patches(module: ModuleType):
    patch_builtins()
    patch_auth_module(module)
    patch_logger()
    # Downstream calls now execute patched behavior rather than static source.
    return auth.check("any-token")
