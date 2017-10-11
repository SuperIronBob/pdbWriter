from idautils import *
from idaapi import *

import inspect
import os

path = os.path.join(os.path.dirname(os.path.abspath(inspect.stack()[0][1])), "functions.txt")
file = open(path, "w")

ea = BeginEA()
for funcea in Functions(SegStart(ea), SegEnd(ea)):
    functionName = GetFunctionName(funcea)
    file.write("S, ")
    file.write(functionName)
    file.write(", ")
    file.write(hex(funcea))
    file.write("\n")

for name in Names():
    file.write("N, ")
    file.write(name[1])
    file.write(", ")
    file.write(hex(name[0]))
    file.write("\n")

file.close()