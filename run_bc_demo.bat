@echo off
setlocal
set DIR=%~dp0
set DIRN=%DIR:~0,-1%
set JAVAC="C:\Program Files\Java\latest\jdk-27\bin\javac.exe"
set JAVA="C:\Program Files\Java\latest\jdk-27\bin\java.exe"
set CP=%DIR%lib\bctls-jdk18on-1.86.1.jar;%DIR%lib\bcprov-jdk18on-1.86.jar;%DIR%lib\bcpkix-jdk18on-1.86.jar;%DIR%lib\bcutil-jdk18on-1.86.jar

echo === [A] BC PQC TLS 1.3 handshake ===
%JAVAC% -encoding UTF-8 -cp "%CP%" -d "%DIRN%" %DIR%BCPqcTlsServer.java %DIR%BCPqcTlsClient.java
if errorlevel 1 ( echo Compile FAILED & exit /b 1 )
echo Compile OK

echo Starting server (port 18443) ...
start "BCServer" %JAVA% -cp "%DIRN%;%CP%" BCPqcTlsServer

echo Wait 3 sec ...
ping 127.0.0.1 -n 4 > nul

echo Starting client ...
%JAVA% -cp "%DIRN%;%CP%" BCPqcTlsClient

echo Done. Close the BCServer window to stop.
endlocal
