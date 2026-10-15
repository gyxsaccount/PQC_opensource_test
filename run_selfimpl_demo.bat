@echo off
setlocal
set DIR=%~dp0
set DIRN=%DIR:~0,-1%
set JAVA="C:\Program Files\Java\latest\jdk-27\bin\java.exe"
set JAVAC="C:\Program Files\Java\latest\jdk-27\bin\javac.exe"
set KEYTOOL="C:\Program Files\Java\latest\jdk-27\bin\keytool.exe"
set KS=%DIR%mldsa.p12

echo === [C] Self-implemented TLS 1.3 + ML-DSA signature ===
echo.
if not exist "%KS%" (
  echo [1/3] Generate ML-DSA-65 self-signed cert ...
  %KEYTOOL% -genkeypair -alias mldsa -keyalg ML-DSA -groupname ML-DSA-65 -dname "CN=SelfImpl PQC,O=Test,C=CN" -storetype PKCS12 -keystore "%KS%" -storepass changeit -keypass changeit -validity 30 >nul 2>&1
  echo  OK
) else (
  echo [1/3] Cert exists, skip
)

echo [2/3] Compile ...
%JAVAC% -encoding UTF-8 -d "%DIRN%" "%DIR%SelfImplementedPqcTls.java"
if errorlevel 1 ( echo Compile FAILED & exit /b 1 )
echo  OK

echo.
echo [3/3] Run self-implemented TLS 1.3 + ML-DSA signature ...
%JAVA% -cp "%DIRN%" SelfImplementedPqcTls "%KS%"

echo.
echo Done.
endlocal
