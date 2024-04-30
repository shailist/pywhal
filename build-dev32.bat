if not exist .venv32 (
  py -3-32 -m venv .venv32
  call .venv32\Scripts\activate
  pip install wheel
  call deactivate
)
call .venv32\Scripts\activate
pip install pybind11 scikit-build-core setuptools_scm pathspec ipython ipdb
set build-dir=build
set SKBUILD_CMAKE_BUILD_TYPE=Debug
pip install --no-build-isolation -ve.
