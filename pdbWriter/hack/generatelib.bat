@echo on
if not EXIST %~dp0\%~2\mspdbcoreexports.txt (
echo generating mspdbcoreexports.txt
dumpbin /exports "%~1\bin\host%~2\%~2\mspdbcore.dll" > %~dp0\%~2\mspdbcoreexports.txt
) ELSE (
echo using existing mspdbcoreexports.txt
)

if not EXIST %~dp0\%~2\mspdbcore.def (
echo generating mspdbcore.def
echo LIBRARY MSPDBCORE > %~dp0\%~2\mspdbcore.def
echo EXPORTS >> %~dp0\%~2\mspdbcore.def
for /f "skip=19 tokens=4" %%a in (%~dp0\%~2\mspdbcoreexports.txt) do (
    if "%%a" NEQ "" echo %%a>> %~dp0\%~2\mspdbcore.def
)
) ELSE (
echo using existing mspdbcore.def

)

if not EXIST %~dp0\%~2\mspdbcore.lib (
echo generating mspdbcore.lib
lib /nologo /DEF:%~dp0\%~2\mspdbcore.def /OUT:%~dp0\%~2\mspdbcore.lib /MACHINE:%~2
) ELSE (
echo using existing mspdbcore.lib

)

if not EXIST %~dp0\mspdbcore.dll (
echo copying mspdbcore.dll
copy /Y "%~1\bin\host%~2\%~2\mspdbcore.dll" %~dp0\%~2\mspdbcore.dll
) ELSE (
echo using existing mspdbcore.dll
)
