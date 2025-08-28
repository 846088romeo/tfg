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

