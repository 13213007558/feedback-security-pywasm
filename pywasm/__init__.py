import platform

from . import arith
from . import core
from . import leb128
from . import log
from . import opcode
from . import quota
if platform.system().lower() in ['darwin', 'linux']:
    from . import wasi
from .core import *
from .quota import *

version = '2.2.3'
