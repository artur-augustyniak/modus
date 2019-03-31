#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PHPTraversalAnalyzer(Analyzer):
    """
    PHP functions used for traversals
    """

    def target_mime_wildcards(self):
        """
        $ file --mime-type file.php
        file.py : text/x-php
        """
        return ["text/x-php"]

    def search_description(self):
        rules = {}
        functions = [
            'readfile', 'readfile ',
            'fopen', 'fopen ',
            'is_readable', 'is_readable ',
            'glob', 'glob '
        ]
        for function in functions:
            idx = "PHP_TRAVERSAL_%s" % (function)
            desc = "Possible %s" % idx
            pattern = "\s*%s\(.*\$" % (function)
            rules[idx] = (pattern, desc)

        return rules


if __name__ == "__main__":
    pass
