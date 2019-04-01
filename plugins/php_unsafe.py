#!/usr/bin/python
# -*- coding: utf-8 -*-

from modus.analyzer import Analyzer


class PHPRUnsafeFuncAnalyzer(Analyzer):
    """
    PHP unsafe functions
    """

    def target_mime_wildcards(self):
        """
        $ file --mime-type file.php
        file.py : text/x-php
        """
        return ["text/x-python"]

    def search_description(self):
        rules = {}
        functions = [
            'rot13',
            'apache_child_terminate',
            'edoced_46esab',
            'strrev',
            'define_syslog_variables',
            'unserialize',
            'serialize'
            'fp',
            'fput',
            'ftp_connect',
            'ftp_exec',
            'ftp_get',
            'ftp_login',
            'ftp_nb_fput',
            'ftp_put',
            'ftp_raw',
            'ftp_rawlist',
            'highlight_file',
            'ini_alter',
            'ini_get_all',
            'ini_restore',
            'inject_code',
            'mysql_pconnect',
            'openlog',
            'passthru',
            'php_uname',
            'phpAds_remoteInfo',
            'phpAds_XmlRpc',
            'phpAds_xmlrpcDecode',
            'phpAds_xmlrpcEncode',
            'posix_getpwuid',
            'posix_kill',
            'posix_mkfifo',
            'posix_setpgid',
            'posix_setsid',
            'posix_setuid',
            'posix_setuid',
            'posix_uname',
            'proc_close',
            'proc_get_status',
            'proc_nice',
            'proc_open',
            'proc_terminate',
            'syslog',
            'xmlrpc_entity_decode ',

        ]
        for function in functions:
            idx = "PHP_UNSAFE_%s" % (function)
            desc = "Possible %s" % idx
            pattern = "\s*%s\(.*\$" % (function)
            rules[idx] = (pattern, desc)

        return rules


if __name__ == "__main__":
    pass
