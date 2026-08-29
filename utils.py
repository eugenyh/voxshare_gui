# -*- coding: utf-8 -*-

"""
Utility functions for the VoxShare application.
"""

import sys
import os

def resource_path(relative_path):
    """ Gets the correct path for resources in EXE and in development """
    if hasattr(sys, "_MEIPASS"):
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    elif "__compiled__" in globals():
        # Nuitka (--onefile or --standalone): this module's own __file__ is
        # rewritten by Nuitka to point at the unpacked runtime location,
        # unlike sys.argv[0] which stays the original exe path.
        base_path = os.path.dirname(os.path.abspath(__file__))
    else:
        base_path = os.path.abspath(".")
 
    return os.path.join(base_path, relative_path)