#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PythonSqliAnalyzer(Analyzer):
    """
    Python SQLi
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
            "SELECT\s.*\%",
            "UPDATE\s.*\%",
            "INSERT\s.*\%",
            "DELETE\s.*\%",
            "WHERE\s.*\%",
            "SELECT\s.*('|\")?\s*\+",
            "UPDATE\s.*('|\")?\s*\+",
            "INSERT\s.*('|\")?\s*\+",
            "DELETE\s.*('|\")?\s*\+",
            "WHERE\s.*('|\")?\s*\+",
        ]
        i = 0
        for pattern in patterns:

            idx = "PYTHON_SQLi_%s" % i
            desc = "Possible %s" % i
            patt = pattern
            rules[idx] = (patt, desc)
            i += 1

        return rules


if __name__ == "__main__":
    pass
