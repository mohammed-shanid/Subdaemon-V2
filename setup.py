from setuptools import setup, find_packages

setup(
    name="subdaemon",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "aiohttp",
        "aiodns",
    ],
    entry_points={
        'console_scripts': [
            'subdaemon=subdaemon.cli.main:main',
        ],
    },
)
