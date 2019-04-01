#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PythonRceAnalyzer(Analyzer):
    """
    Python Rce
    """

    def target_mime_wildcards(self):
        """
        $ file --mime-type file.py
        file.py : text/x-python
        """
        return ["text/x-python"]

    def search_description(self):
        rules = {}

        patterns = [
            "subprocess.*\(.*('|\")\s*",
            "os\.system\(",
            "exec\(",
            "eval\("

        ]
        i = 0
        for pattern in patterns:

            idx = "PYTHON_RCE_%s" % i
            desc = "Possible %s" % i
            patt = pattern
            rules[idx] = (patt, desc)
            i += 1

        return rules


if __name__ == "__main__":
    pass
