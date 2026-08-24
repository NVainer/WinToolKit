"""Device Control Console -- a GUI + CLI front end for pnputil and the Windows
Configuration Manager.

See ``README.md``.  Public entry points:

* :func:`dcc.model.build` -- take a snapshot of devices and the driver store
* :func:`dcc.server.serve` -- run the local web console
* ``python -m dcc`` -- the command line
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
