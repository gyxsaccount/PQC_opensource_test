@echo off
setlocal enabledelayedexpansion
set DIR=%~dp0
set DIRN=%DIR:~0,-1%
set JAVA="C:\Program Files\Java\latest\jdk-27\bin\java.exe"
set JAVAC="C:\Program Files\Java\latest\jdk-27\bin\javac.exe"
set CP=%DIRN%\lib\*

echo === Jetty 12 PQC Migration Demo - All Migration Points ===
echo.
echo [0/9] Compile all demo sources ...
%JAVAC% -encoding UTF-8 -cp "%CP%" -d "%DIRN%\out" %DIRN%\src\*.java
if errorlevel 1 ( echo Compile FAILED & exit /b 1 )
echo  OK
echo.
echo [1/9] MigPoint1+7: Jetty HTTPS server + HttpClient (X25519MLKEM768) ...
start "JettyPqcServer" %JAVA% -cp "%CP%;%DIRN%\out" JettyPqcServer "%DIRN%\etc\keystore.p12" 18443
ping 127.0.0.1 -n 4 > nul
%JAVA% -cp "%CP%;%DIRN%\out" JettyPqcClient https://localhost:18443/hello
echo.
echo [2/9] MigPoint2: ML-DSA cert blocker (Jetty SslContextFactory + JSSE) ...
%JAVA% -cp "%CP%;%DIRN%\out" MldsaCertBlockTest "%DIRN%\etc\mldsa.p12" 18445
echo.
echo [3/9] MigPoint3: Digest auth hash migration (SHA-384) ...
%JAVA% -cp "%CP%;%DIRN%\out" DigestAuthPqcTest 18446
echo.
echo [4/9] MigPoint4: Password/Realm hash migration ...
%JAVA% -cp "%CP%;%DIRN%\out" PasswordHashPqcTest
echo.
echo [5/9] MigPoint5: Session security audit ...
%JAVA% -cp "%CP%;%DIRN%\out" SessionSecurityPqcTest
echo.
echo [6/9] MigPoint6: OIDC/JWT algorithm assessment ...
%JAVA% -cp "%CP%;%DIRN%\out" OidcJwtPqcTest
echo.
echo [7/9] MigPoint8: HTTP/3 (QUIC) assessment ...
%JAVA% -cp "%CP%;%DIRN%\out" Http3PqcTest
echo.
echo [8/9] Stop Jetty server ...
taskkill /FI "WINDOWTITLE eq JettyPqcServer*" /F >nul 2>&1
echo  OK
echo.
echo [9/9] Done. See report Jetty_PQC_Migration_Report.md
endlocal
