#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys


# def get_os_name() -> str:
def get_os_name():
    plat = sys.platform

    if plat.startswith('linux'):
        return 'linux64'
    elif plat == 'win32':
        return 'win64'
    elif plat == 'darwin':
        return 'osx64'
    else:
        raise RuntimeError('Unsupported platform {!r}'.format(plat))


# def get_file_extension() -> str:
def get_file_extension():
    return '.exe' if sys.platform == 'win32' else ''
