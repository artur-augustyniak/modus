#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PythonTraversalAnalyzer(Analyzer):
    """
    PHP functions used for traversals
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
            "(\.|\s|^)open\(\s*[a-zA-Z0-9]\s*(\,|\()?",
        ]
        i = 0
        for pattern in patterns:

            idx = "PYTHON_PTRAV_%s" % i
            desc = "Possible %s" % i
            patt = pattern
            rules[idx] = (patt, desc)
            i += 1

        return rules


if __name__ == "__main__":
    pass
