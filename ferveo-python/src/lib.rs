use ferveo::bindings_python::*;
use pyo3::prelude::*;

#[pymodule]
fn _ferveo(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    make_ferveo_py_module(py, m)
}
