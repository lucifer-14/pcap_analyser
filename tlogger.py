"""
Script: tlogger.py
Description: To handle the repeated task of logging the outputs.
Author: Thar Htet Nyan
Date: August 2022
"""


import sys
from io import TextIOWrapper


def logger(log: str, out_file: TextIOWrapper, is_error: bool = False) -> None:
    """ Prints and stores the log in output file """
    if is_error:
        sys.stderr.write(log)
        print(log, end="\n\n", file=out_file, flush=True)
    else:
        print(log)
        print(log, file=out_file, flush=True)


if __name__ == "__main__":
    with open('sample_file.txt', 'wt', encoding='utf-8') as sample_file:
        logger("Sample LOG", file=sample_file)
