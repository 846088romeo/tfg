# Casos de prueba 
Protocolos vulnerables a ataques de ```replay```

## Estructura carpeta


```
casos_prueba/
├── anbx_files/     <-------------- protocolos AnBx (originales y con MITM)
├── input_files/    <-------------- trazas de ejecución de los simuladores de protocolos (cada protocolo tiene 
├──                                 n trazas, donde n es el número de roles del protocolo)
├── output_files/   <-------------- trazas de ejecución sintéticas obtenidas con el "logextractor.py"
├── scripts/        <-------------- shell scripts para la ejecución de los protocolos
├── src/            <-------------- simuladores de protocolos (Java) - los con MITM modificados "manualmente"
├── logextractor.py <-------------- sintentiza las trazas de ejecución y produce un fichero en formato .csv
└── README.md       <------------ este documento
```
