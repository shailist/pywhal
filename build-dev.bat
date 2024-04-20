if not exist .venv (
  py -m venv .venv
)
call .venv\Scripts\activate
pip install pybind11 scikit-build-core setuptools_scm pathspec
set build-dir=build
set SKBUILD_CMAKE_BUILD_TYPE=Debug
pip install --no-build-isolation -ve.
