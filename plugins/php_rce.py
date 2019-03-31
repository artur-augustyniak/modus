#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PHPRemoteCommandExec(Analyzer):
    """
    PHP Remote Command Execution (RCE)
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
            'call_user_func',
            'call_user_func',
            'function_exists',
            'function_exists',
            'shell_exec',
            'system',
            'popen',
            'exec',
            'escapeshellarg',
            'escapeshellcmd',
            'apache_setenv'
        ]
        for function in functions:
            idx = "PHP_RCE_%s" % (function)
            desc = "Possible %s" % idx
            pattern = "\s*%s\(.*\$" % (function)
            rules[idx] = (pattern, desc)

        return rules


if __name__ == "__main__":
    pass
