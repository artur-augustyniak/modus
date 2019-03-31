#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PHPInclusionAnalyzer(Analyzer):
    """
    PHP include with variable
    """

    def target_mime_wildcards(self):
        """
        $ file --mime-type file.php
        file.py : text/x-php
        """
        return ["text/x-php"]

    def search_description(self):
        methods = ['GET', 'POST', 'REQUEST', 'COOKIE', 'SERVER', 'FILES']
        rules = {}
        functions = [
            'include',
            'include_once',
            'require',
            'require_once ',

        ]
        for function in functions:
            
            idx = "PHP_UNSAFE_FILE_INC_%s" % (function)
            desc = "Possible %s" % idx
            pattern = "\s*%s\(.*\$" % (function)
            rules[idx] = (pattern, desc)

        return rules


if __name__ == "__main__":
    pass
