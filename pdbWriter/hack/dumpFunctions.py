from idautils import *
from idaapi import *

import inspect
import os

path = os.path.join(os.path.dirname(os.path.abspath(inspect.stack()[0][1])), "functions.txt")
file = open(path, "w")

ea = BeginEA()
for funcea in Functions(SegStart(ea), SegEnd(ea)):
    functionName = GetFunctionName(funcea)
    file.write(functionName)
    file.write(", ")
    file.write(hex(funcea))
    file.write("\n")

file.close()