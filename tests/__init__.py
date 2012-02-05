# -*- coding: utf-8 -*-

import os

def get_resource(filename):
    return os.path.join(os.path.dirname(__file__), 'data', filename)
