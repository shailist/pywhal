# pywhal

[![Actions Status][actions-badge]][actions-link]
[![Documentation Status][rtd-badge]][rtd-link]

[![PyPI version][pypi-version]][pypi-link]
[![Conda-Forge][conda-badge]][conda-link]
[![PyPI platforms][pypi-platforms]][pypi-link]

[![GitHub Discussion][github-discussions-badge]][github-discussions-link]

<!-- SPHINX-START -->

<!-- prettier-ignore-start -->
[actions-badge]:            https://github.com/shailist/pywhal/workflows/CI/badge.svg
[actions-link]:             https://github.com/shailist/pywhal/actions
[conda-badge]:              https://img.shields.io/conda/vn/conda-forge/pywhal
[conda-link]:               https://github.com/conda-forge/pywhal-feedstock
[github-discussions-badge]: https://img.shields.io/static/v1?label=Discussions&message=Ask&color=blue&logo=github
[github-discussions-link]:  https://github.com/shailist/pywhal/discussions
[pypi-link]:                https://pypi.org/project/pywhal/
[pypi-platforms]:           https://img.shields.io/pypi/pyversions/pywhal
[pypi-version]:             https://img.shields.io/pypi/v/pywhal
[rtd-badge]:                https://readthedocs.org/projects/pywhal/badge/?version=latest
[rtd-link]:                 https://pywhal.readthedocs.io/en/latest/?badge=latest

<!-- prettier-ignore-end -->

## Building on 32 bit

You'll need OpenSSL 1.1.1.2100 for the buildsystem to function.  
On 64 bit it isn't an issue and just works, on 32 bit you need to install it manually.  
I recommend using Chocolatey and running:
```bash
choco install openssl --version 1.1.1.2100 --x86
```
