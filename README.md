# Extensión de AnBxTools para ataques de replay y wff-checks

Este repositorio contiene el código y los casos de prueba desarrollados en el marco del **Trabajo de Fin de Grado**.  
La contribución principal consiste en la extensión del compilador **AnBxTools** para:

- Incorporar el operador `~` que modela **mensajes de replay**.
- Generar representaciones intermedias `NAReplay` y `JReplay`.
- Integrar comprobaciones de buena formación (**wff-checks**) adicionales, en particular sobre proyecciones de mensajes cifrados.
- Facilitar la validación práctica mediante ejecución en **Java** y análisis de trazas.

---

## 📂 Estructura del repositorio

- **`anbx_new/`**  
  Contiene la versión extendida del compilador AnBxTools (`anbxc`) escrita en **Haskell**.  
  Aquí se han implementado las extensiones (`~`, `NAReplay/JReplay`, `wff-checks`).  
  Incluye su propio `README.md` con instrucciones de compilación y uso.

- **`casos_prueba/`**  
  Conjunto de protocolos y ejemplos vulnerables, junto con el script **`logextractor`** para posprocesar las trazas generadas en Java.  
  Se incluyen logs que muestran ataques de replay y registros de `wff-check`.

- **`ofmc2024/`**  
  Versión del model checker **OFMC** utilizada para generar contraejemplos.  
  Este directorio no contiene modificaciones, se conserva solo como referencia.

---

## ⚙️ Construcción y uso

### 1. Compilador extendido (`anbx_new`)

El directorio `anbx_new/` contiene la implementación del compilador extendido, dividido en varios submódulos:

- **`AnBx2/`** → Código fuente en **Haskell** del compilador `anbxc` extendido.  
  - `src/` → implementación del compilador.  
  - `STemplates/` → plantillas Java usadas para la generación de código.  
  - `bin/` → ejecutables (`anbxc_new.exe`, versión extendida; `anbxc_ant.exe`, versión previa).  
  - `AnBx3.cabal` → configuración de **Cabal** para compilar el proyecto.  
  - `build_anbxc.ps1` → script en PowerShell que automatiza la compilación y mueve el binario final a `bin/anbxc_new.exe`.

- **`AnBxJ/`** → Biblioteca Java de soporte para los protocolos generados.  
  - `src/` y `doc/` → código y documentación de la librería.  
  - `AnBxJ.jar` → librería compilada lista para usarse.  
  - `bcprov-jdk18on-1.80.jar` → dependencia de BouncyCastle para primitivas criptográficas.

- **`casestudies/`** → protocolos de prueba en formato `.anbx` y `.anb`.  
  Se compilan con `anbxc_new` y sus correspondientes clases Java se generan en `genAnBx/`.

- **`genAnBx/`** → código **Java generado automáticamente** para los casos de prueba.  

- **`bin/`** → clases compiladas (`.class`) de los protocolos.  

---

#### 🔨 Compilación de `anbxc_new`

Existen dos formas de compilar el compilador extendido:  

---

##### 🔹 Windows

En Windows basta con ejecutar el script PowerShell incluido, que automatiza todo el proceso:

```powershell
cd anbx_new/AnBx2
./build_anbxc.ps1
```

Esto compilará el proyecto con Cabal y moverá el ejecutable resultante a:

    anbx_new/AnBx2/bin/anbxc_new.exe

---

##### 🔹 Compilación general (Linux/Mac/otros entornos)

Ir al directorio del compilador:

```powershell
    cd anbx_new/AnBx2
```

Compilar con Cabal:

```powershell
    cabal build
```

Localizar el binario generado (ejemplo para GHC 8.6.5 en Windows, la ruta puede variar):

    dist-newstyle/build/x86_64-windows/ghc-8.6.5/anbxc-2025.1/x/anbxc/build/anbxc/anbxc.exe

Copiarlo manualmente a `bin/` y renombrarlo como:

    anbx_new/AnBx2/bin/anbxc_new.exe
