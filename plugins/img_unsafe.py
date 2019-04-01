#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class ImgUnsafeAnalyzer(Analyzer):
    """
    unsafe functions
    """

    def target_mime_wildcards(self):

        return ["image/*"]

    def search_description(self):
        rules = {}
        patterns = [
            'system\(',
            'strrev',
            '<\?php',


        ]
        i = 0
        for pattern in patterns:
            idx = "BIN_UNSAFE_%s" % (pattern)
            desc = "Possible %s" % idx
            patt = pattern
            rules[idx] = (patt, desc)
            i += 1
        return rules


if __name__ == "__main__":
    pass
