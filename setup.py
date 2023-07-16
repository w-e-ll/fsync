# -*- coding: utf-8 -*-
import os
from setuptools import setup, find_packages


def read(*r_names):
    return open(os.path.join(os.path.dirname(__file__), *r_names)).read()


version = '1.1'

long_description = (
    read('fsync/docs/about.rst') + '\n\n' +
    read('fsync/docs/changes.rst') + '\n\n' +
    read('fsync/docs/contributors.rst')
)


setup(
    name='fsync',
    version=version,
    description="File synchronizer.",
    long_description=long_description,

    classifiers=[
        "License :: Other/Proprietary License",
        "Natural Language :: English",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.10.9",
    ],

    keywords='file transfer synchronization ftp sftp',
    author='Valentin Sheboldaev',
    license='BSD',
    packages=find_packages(exclude=['ez_setup', 'tests']),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'arrow',
        'ftputil',
        'pysftp',
        'python-crontab',
        'PyYAML',
        'setuptools',
    ],

    entry_points={
        'console_scripts': [
            # Generic entrypoints
            'fsync = fsync.fsync:cli'
        ],
    }
)
