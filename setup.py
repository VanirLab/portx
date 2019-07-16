# !/usr/bin/env python3
# encoding: UTF-8

import re
import os
import ast
from setuptools import setup, find_packages
# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

cversion = re.compile(r'__version__\s+=\s+(.*)')
with open('portx.py') as f:
    version = "1.0.0"

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()

setup(
 name='Portx',
 version=version,
 url='https://github.com/VanirLab/portx',
 license='MIT',
 author='Chris Pro',

 description='A small port yoctoarchitecture!' 
             'and good intentions',
 long_description=__doc__,

 packages=find_packages(),
  include_package_data=True,
 #scripts=["portx"],
 zip_safe=False,
 platforms='any',


 classifiers=[
 'Development Status :: 1 - Beta',
 'Environment :: Web Environment',
 'Intended Audience :: Developers',
 'License :: OSI Approved :: MIT License',
 'Operating System :: OS Independent',
 'Programming Language :: Python',
 'Programming Language :: Python :: 2',

 'Programming Language :: Python :: 2.6',
 'Programming Language :: Python :: 2.7',
 'Programming Language :: Python :: 3',
 'Programming Language :: Python :: 3.3',
 'Programming Language :: Python :: 3.4',
 'Programming Language :: Python :: 3.5',
 'Programming Language :: Python :: 3.7',
 'Programming Language :: Python :: 3.9',
 'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
 'Topic :: Software Development :: Libraries :: Python Modules'
 ],
 entry_points='''
 [console_scripts]
 portx=portx.cli:main
 '''
)
