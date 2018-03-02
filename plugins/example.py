#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class BasicXssAnalyzer(Analyzer):
    """
    this is example module
    """

    def target_mime_wildcards(self):
        return ["text/plain*"]

    def search_description(self):
        return {
            "warn:TODO:marker": ("*TODO", "it looks like we got TODO marker."),
            "warn:FIXME:marker": ("*FIXME", "it looks like we got FIXME marker."),
        }


if __name__ == "__main__":
    pass
