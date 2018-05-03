#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class ResourceMgmtAnalyzer(Analyzer):
    """
    this is example module
    """

    def target_mime_wildcards(self):
        """
        $ file --mime-type file.py 
        file.py : text/x-python
        """
        return ["text/x-python"]

    def search_description(self):
        return {
            "POSSIBLE RESOURCE LEAK": ("^[^#]*=\sopen*\(", "open without context manager"),
        }


if __name__ == "__main__":
    pass
