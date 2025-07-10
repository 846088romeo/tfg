# PowerShell script para compilar y mover el ejecutable de AnBx

# Limpiar la build previa
# Write-Host "Limpiando con 'cabal clean'..."
# cabal clean

# Compilar el proyecto
Write-Host "Compilando con 'cabal build'..."
$cabalBuild = cabal build 2>&1

# Comprobar si la compilación tuvo éxito
if ($LASTEXITCODE -eq 0) {
    Write-Host "Compilación exitosa."

    # Ruta del ejecutable generado
    $source = ".\dist-newstyle\build\x86_64-windows\ghc-8.6.5\anbxc-2025.1\x\anbxc\build\anbxc\anbxc.exe"

    # Verificar que el ejecutable existe
    if (Test-Path $source) {
        # Copiar el ejecutable a la raíz
        Copy-Item $source -Destination ".\" -Force
        Write-Host "Ejecutable copiado a la raíz."

        # Ruta del archivo de destino final
        $finalDest = ".\bin\anbxc_new.exe"

        # Eliminar el archivo anterior si existe
        $oldBin = ".\bin\anbxc_new.exe"
        if (Test-Path $oldBin) {
            Remove-Item $oldBin -Force
            Write-Host "Archivo anterior eliminado de ./bin"
        }

        # Renombrar y mover el ejecutable nuevo
        Rename-Item ".\anbxc.exe" "anbxc_new.exe"
        Move-Item "anbxc_new.exe" ".\bin\"
        Write-Host "Nuevo ejecutable movido a ./bin como 'anbxc_new.exe'"
    } else {
        Write-Host "ERROR: No se encontró el ejecutable compilado en: $source"
    }

} else {
    Write-Host "ERROR: Falló la compilación."
    Write-Host "Salida del compilador:"
    Write-Host $cabalBuild
}
