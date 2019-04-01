#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PythonSerialisationAnalyzer(Analyzer):
    """
    Python Serialisation
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
            '\.load\(',
            '\.loads\(',
            'cPickle',
            'pickle'
        ]
        i = 0
        for pattern in patterns:
            idx = "PYTHON_SERIALISATION_%s" % (i)
            desc = "Possible %s" % idx
            patt = pattern
            rules[idx] = (patt, desc)
            i += 1
        return rules


if __name__ == "__main__":
    pass
