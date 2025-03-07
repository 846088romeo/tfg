@echo off
REM Script para ejecutar archivos .AnBx en Windows

REM Verifica que se haya proporcionado un archivo .AnBx como argumento
if "%~1"=="" (
    echo Uso: %~nx0 <archivo.AnBx>
    exit /b 1
)

REM Nombre del archivo .AnBx (sin extensión)
set filename=%~n1

REM Ruta al compilador AnBx (ajusta según tu instalación)
set ANBXC=AnBx2\bin\anbxc.exe

REM Rutas definidas en el archivo .cfg
set PATH_JAVA_DEST=../../genAnBx/src/
set KEY_PATH=../../keystore/
set ANBXJ_PATH=../../../AnBxJ

REM Ruta al archivo AnBxJ.jar (en la carpeta AnBxJ)
set ANBXJ_JAR=%ANBXJ_PATH%/AnBxJ.jar

REM Directorio de salida para los archivos generados
set OUTPUT_DIR=%PATH_JAVA_DEST%

REM 1. Crear la carpeta de salida (si no existe)
if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
)

REM 2. Compilar el archivo .AnBx a Java
echo Compilando %1 a Java en la carpeta %OUTPUT_DIR%...
"%ANBXC%" "casestudies\%1" -out:Java -d "%OUTPUT_DIR%"

REM Verifica si la compilación fue exitosa
if errorlevel 1 (
    echo Error al compilar el archivo .AnBx.
    exit /b 1
)

REM 3. Compilar el código Java generado
echo Compilando el código Java generado...
javac -cp "%ANBXJ_JAR%" -d "%OUTPUT_DIR%" "%OUTPUT_DIR%\%filename%\*.java"

REM Verifica si la compilación fue exitosa
if errorlevel 1 (
    echo Error al compilar el código Java.
    exit /b 1
)

REM 4. Ejecutar los roles del protocolo
echo Ejecutando el protocolo...
echo Ejecutando ROLE_A...
start "ROLE_A" cmd /c java -cp "%OUTPUT_DIR%\*;%ANBXJ_JAR%" %filename%.%filename% -r ROLE_A -verbose

REM Esperar un momento para que ROLE_A esté listo
timeout /t 2 >nul

echo Ejecutando ROLE_B...
java -cp "%OUTPUT_DIR%\*;%ANBXJ_JAR%" %filename%.%filename% -r ROLE_B -verbose

REM Esperar a que ambos roles terminen
wait

echo Ejecución completada.