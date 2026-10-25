"""Authorized assessment framework backend."""
import os

# Disable compiled Cython C-extensions in SQLAlchemy. On systems with Windows
# Defender Application Control (WDAC), AppLocker, or strict code-integrity policies,
# dynamic .pyd libraries in user workspaces are blocked from loading. Setting this
# ensures SQLAlchemy smoothly uses its bundled pure-Python implementations without
# weakening system security policies or attempting to bypass operating system controls.
os.environ.setdefault('DISABLE_SQLALCHEMY_CEXT', '1')
