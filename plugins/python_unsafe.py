#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PythonUnsafeAnalyzer(Analyzer):
    """
    Python Unsafe
    """

    def target_mime_wildcards(self):
        """
        $ file --mime-type file.py
        file.py : text/x-python
        """
        return ["text*"]

    def search_description(self):
        rules = {}

        patterns = [
            "verify=False",
            'rot13'

        ]
        i = 0
        for pattern in patterns:

            idx = "PYTHON_UNSAFE_%s" % i
            desc = "Possible %s" % i
            patt = pattern
            rules[idx] = (patt, desc)
            i += 1

        return rules


if __name__ == "__main__":
    pass
