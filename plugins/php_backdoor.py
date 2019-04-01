#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PHPBackdoorAnalyzer(Analyzer):
    """
    PHP Possible backdors
    """

    def target_mime_wildcards(self):
        """
        $ file --mime-type file.php
        file.py : text/x-php
        """
        return ["text/x-php"]

    def search_description(self):
        rules = {
            "PHP_BASE64_BDOR": ("gzinfl|base64_d.*\(|eval\(", "Possible simple based backdoor"),
            "PHP_OBFUSCATION_BDOR": (
                "\\\\x[0-9A-Fa-f]{2}", 
                    
                    "Possible simple obfuscated backdoor"),


                
        }

        return rules


if __name__ == "__main__":
    pass
