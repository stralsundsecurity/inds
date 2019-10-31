from distutils.core import setup
from Cython.Build import cythonize



setup(
    ext_modules = cythonize(module_list = ("network_layers/*.pyx",
                                            "utils/*.pyx",
                                           "*.pyx"),
                            annotate=True)
                            #compiler_directives={'language_level' : '2'})
)