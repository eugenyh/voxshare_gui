# -*- coding: utf-8 -*-

"""
Utility functions for the VoxShare application.
"""

import sys
import os

def resource_path(relative_path):
    """ Gets the correct path for resources in EXE and in development """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)