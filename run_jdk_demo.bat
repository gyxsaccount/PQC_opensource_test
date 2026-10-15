@echo off
setlocal enabledelayedexpansion
set DIR=%~dp0
set DIRN=%DIR:~0,-1%
set JAVA="C:\Program Files\Java\latest\jdk-27\bin\java.exe"
set JAVAC="C:\Program Files\Java\latest\jdk-27\bin\javac.exe"
set KEYTOOL="C:\Program Files\Java\latest\jdk-27\bin\keytool.exe"
set KS=%DIR%server.p12

echo === [B] JDK native PQC Demo ===
echo.
echo [1/4] Generate self-signed cert (keytool EC) ...
if exist "%KS%" del "%KS%"
%KEYTOOL% -genkeypair -alias server -keyalg EC -groupname secp256r1 -dname "CN=JDK PQC TLS,O=JDK,C=CN" -storetype PKCS12 -keystore "%KS%" -storepass changeit -keypass changeit -validity 365 >nul 2>&1
echo  OK: server.p12
echo [2/4] Compile ...
%JAVAC% -encoding UTF-8 -d "%DIRN%" "%DIR%JdkPqcPrimitives.java" "%DIR%JdkPqcTlsServer.java" "%DIR%JdkPqcTlsClient.java"
if errorlevel 1 ( echo Compile FAILED & exit /b 1 )
echo  OK
echo.
echo [3/4] ML-KEM / ML-DSA primitives ...
%JAVA% -cp "%DIRN%" JdkPqcPrimitives
echo.
echo [4/4] JDK native X25519MLKEM768 TLS 1.3 handshake ...
echo  Starting server (port 18444) ...
start "JdkPqcServer" %JAVA% -cp "%DIRN%" JdkPqcTlsServer "%KS%"
ping 127.0.0.1 -n 4 > nul
echo  Starting client ...
%JAVA% -cp "%DIRN%" JdkPqcTlsClient

:cleanup
if exist "%KS%" del "%KS%"
echo Done. Close the JdkPqcServer window to stop.
endlocal
