### Informe proyecto final de Seguridad 
Este informe pertenece al proyecto final de Seguridad de los estudiantes Alejandro Garcia y Diego Andres Torres. El proyecto consiste en un firmador y verificador de firmas.

### ¿Cómo hicieron el programa?
Inicialmente, tuvimos que instruirnos en el API criptográfica de java mediante videos y documentación de la misma. Se utilizo el paquete javax.crypto para los cifrados y el paquete Security para la creacion de llaves y el firmado de archivos.
Luego ambos nos dedicamos a la codificación, trabajando tanto en espacios compartidos como por separado para lograr terminar el proyecto lo mas rápido posible, dado que por una complicación de la que hablaremos más adelante, el tiempo que teniamos era escazo.
Para cerciorarnos de que el proyecto habia quedado bien y funcionaba correctamente relizamos pruebas como cambiar el archivo y luego comprobar el firmado (debe salir que no coincide o que fue modificado).

### ¿Qué dificultades tuvieron?
La principal dificultad que tuvimos fue que primero habiamos escogido otro proyecto pero tuvimos muchas complicaciones y decidimos cambiarlo, puesto que ya habiamos investigado un poco sobre el firmador, consideramos que lo podíamos sacar con menos dificultades y le consultamos al profesor si podiamos hacer el cambio.
Haciendo el firmador tuvimos un error pues decidimos hacer las llaves con Base64 encoder y se nos presentaba un error al momento de desencriptar la llave privada, para arreglarlo decidimos cambiar el Base64 encoder por KeyPairGenerator.

### Conclusiones
Durante este trabajo aprendimos que aunque se este estresado y la situacion este complicada ya sea por tiempo o por dificultades que se presenten durante el trabajo, hay que mantener la mente fria y enfocarse en resolver esas dificultades para asi lograr el objetivo de completar el proyecto en el tiempo estipulado.
Tambien aprendimos a manejar APIs de seguridad en java lo cual es muy importante en nuestra carrera pues la seguridad es la base de todo, sin ciberseguridad absolutamente todo el mundo esta en peligro.