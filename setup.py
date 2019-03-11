#/usr/bin/env python2
import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as f:
        return f.read()

setup(
    name = "pyrsp",
    version = "0.4.0.1",
    author = "Stefan Marsiske",
    author_email = "s@ctrlc.hu",
    description = ("simple GDB remote serial protocol wrapper"),
    license = "AGPLv3",
    keywords = "GDB remote debugging JTAG embedded scripting",
    url = "https://github.com/stef/pyrsp",
    packages = ['pyrsp'],
    entry_points = {
       'console_scripts': [
          'pyrsp = pyrsp.rsp:main',
          ],
       },
    long_description=read('README.org'),
    install_requires = ("pyelftools", "pyserial", "construct", "six"),
    classifiers = ["Development Status :: 4 - Beta",
                   "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
                   ],
)
