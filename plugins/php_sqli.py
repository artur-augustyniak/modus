#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PHPSqliAnalyzer(Analyzer):
    """
    PHP SQLi
    """

    def target_mime_wildcards(self):
        """
        $ file --mime-type file.php
        file.py : text/x-php
        """
        return ["text/x-php"]

    def search_description(self):
        rules = {}

        patterns = [
            ".*INFILE.*",
            "SELECT\s.*\$",
            "UPDATE\s.*\$",
            "INSERT\s.*\$",
            "DELETE\s.*\$",
            "WHERE\s.*\$",
        ]
        i=0
        for pattern in patterns:

            idx = "PHP_SQLi_%s" % i
            desc = "Possible %s" % idx
            patt = pattern
            rules[idx] = (patt, desc)
            i+=1

        return rules


if __name__ == "__main__":
    pass
