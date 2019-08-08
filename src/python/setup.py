from setuptools import setup

with open('readme.rst', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="randombit/botan",
    version="2.12.0",
    author="First Name",
    author_email="<someone>@randombit.net",
    description="Crypto and TLS for Modern C++",
    long_description=long_description,
    license="BSD-2-Clause",
    long_description_content_type="text/x-rst",
    url="https://github.com/randombit/botan",
    packages=['botan2'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
)
