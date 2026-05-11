# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2020 Eric Lesiuta

import sys

from .cli import start_picosnitch

if __name__ == "__main__":
    sys.exit(start_picosnitch())
