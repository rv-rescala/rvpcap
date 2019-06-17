from setuptools import setup, find_packages

setup(
    name='rvpcap',
    entry_points={
        'console_scripts': [
            'rvpcap = rvpcap.main:main',
        ],
    },
    version='1',
    description='TBD',
    author='RV',
    author_email='yo-maruya@rescala.jp',
    install_requires=['dpkt'],
    url='TBD',
    license=license,
    packages=find_packages(exclude=('tests'))
)
