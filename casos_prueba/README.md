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

The ```logextractor``` folder includes the current post-processing script together
with the examples. In particular:

- **`anbx_files/`**: includes the AnBx files of protocol specification.
- **`input_files/`**: includes the execution files produced by the ```AnBx``` tool to be processed.
- **`output_files/`**: include the processed execution file (output of the post-processing).
- **`logextractor.py`**: the Python script to be used for postprocessing.


## Usage Notes
- The scripts can be executed with the command line:

```
> python3 logsextractor.py <protocol_name>
```
where ```<protocol_name>``` is the name of the protocol (```.AnBx``` file name in ```anbx_files`` folder)

The output file (```.csv``` format) is saved in the ```output_files``` folder.
More details about the format [here](https://github.com/simber72/CriptoSimulator/blob/main/doc/protocols.md)
