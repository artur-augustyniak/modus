modus_operandi
===============

This tool is based on Cody Sixteen work.
Check his great work:
https://code610.blogspot.com/ 


clear && python -B ./modus.py /tmp/DVWA/ 
clear && python -B ./modus.py /tmp/DVWA/ | grep -v vendors



$ python -B ./modus.py -h
usage: modus.py [-h] [-f REGEXP] [-p NUMBER] [-t NUMBER] [-r PATH] [-s BOOL]
                [-l]
                PATH

[--] modus v0.7 [--]

positional arguments:
  PATH                  Source files directory.

optional arguments:
  -h, --help            show this help message and exit
  -f REGEXP, --filter REGEXP
                        File name wildcard. Default value is "*".
  -p NUMBER, --proc NUMBER
                        Worker processes. Default value is (8 - 1). Max
                        possible value is (8 * 3)
  -t NUMBER, --threads NUMBER
                        Internal worker parallelism. Default value is 10.
                        Value in inclusive range <1-100>.
  -r PATH, --repo PATH  Custom plugins dir. Default value is /media/DATA/TERMI
                        NAL/locked_shields/linux_disovery_scripts/modus_operan
                        di/plugins.
  -s BOOL, --smc BOOL   Strict mime match. WARNING! Disabling this will run
                        all enabled analyzers against all types of files
                        ignoring potential extension-content inconsistency
                        Default value is True.
  -l, --list            List available checks.
