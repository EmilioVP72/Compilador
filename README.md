#AQUI SE IRA DETALLANDO LA CONSTRCCION DEL LEGUAJE LIBRE DE CONTEXTO PARA NUESTRO COMPILADOR 

# Estructura Principal
PROGRAMA → CLASS_DECLARATION MAIN
MAIN → block init DECLARACIONES MÉTODOS BLOQUES end init

# Clases y Metodos
CLASS_DECLARATION → class IDENTIFICADOR { DECLARACIONES MÉTODOS }
MÉTODOS → MÉTODO MÉTODOS | ε
MÉTODO → TIPO_DATO IDENTIFICADOR ( PARAMETROS ) { BLOQUE }
PARAMETROS → TIPO_DATO IDENTIFICADOR MÁS_PARAM | ε
MÁS_PARAM → , TIPO_DATO IDENTIFICADOR MÁS_PARAM | ε

# Declaraciones y Asignaciones 
DECLARACIONES → DECLARACIÓN DECLARACIONES | ε
DECLARACIÓN → TIPO_DATO IDENTIFICADOR ASIGNACIÓN ;
ASIGNACIÓN → = EXPRESIÓN | ε
TIPO_DATO → full | half | bin | crs | chain

# Identificadores y Valores
IDENTIFICADOR → LETRA LETRAS_DIGITOS
LETRAS_DIGITOS → LETRA LETRAS_DIGITOS | DIGITO LETRAS_DIGITOS | ε
VALOR → ENTERO | FLOTANTE | BOOLEANO | CADENA | EXPRESIÓN

# Operadores y Expresiones
EXPRESIÓN → EXPRESIÓN ARITMETICO EXPRESIÓN | EXPRESIÓN COMPARACIÓN EXPRESIÓN | EXPRESIÓN LÓGICO EXPRESIÓN | ( EXPRESIÓN ) | IDENTIFICADOR | VALOR
ARITMETICO → + | - | * | / | % | **
COMPARACIÓN → == | != | > | >= | < | <= | === | eql? | <=>
LÓGICO → && | || | ! | not
TERNARIO → IDENTIFICADOR ? EXPRESIÓN : EXPRESIÓN

# Estructuras de Control
ESTRUCTURA_CONTROL → CONDICIÓN | BUCLE | SWITCH | MATRIZ
CONDICIÓN → if ( EXPRESIÓN ) { BLOQUE } ELSE_OPCIONAL
ELSE_OPCIONAL → else { BLOQUE } | ε
BUCLE → while ( EXPRESIÓN ) { BLOQUE } | for ( DECLARACIÓN ; EXPRESIÓN ; ASIGNACIÓN ) { BLOQUE }
SWITCH → switch ( EXPRESIÓN ) { CASES }
CASES → case EXPRESIÓN : BLOQUE CASES | default : BLOQUE | ε
MATRIZ → IDENTIFICADOR [ EXPRESIÓN ] | IDENTIFICADOR [ EXPRESIÓN ][ EXPRESIÓN ]

# Bloques y Funciones 
BLOQUES → BLOQUE BLOQUES | ε
BLOQUE → INSTRUCCIÓN BLOQUE | ε
INSTRUCCIÓN → ASIGNACIÓN | ESTRUCTURA_CONTROL | LLAMADA_FUNCIÓN | IMPRIMIR
IMPRIMIR → puts( ARGUMENTOS )
ARGUMENTOS → EXPRESIÓN MÁS_ARG
MÁS_ARG → , EXPRESIÓN MÁS_ARG | ε

# Funciones y Operaciones en Listas 
LLAMADA_FUNCIÓN → IDENTIFICADOR ( ARGUMENTOS )
LISTA → [ ELEMENTOS ]
ELEMENTOS → EXPRESIÓN MÁS_ELEMENTOS | ε
MÁS_ELEMENTOS → , EXPRESIÓN MÁS_ELEMENTOS | ε
AGREGAR → IDENTIFICADOR << EXPRESIÓN
ELIMINAR → IDENTIFICADOR . delete( EXPRESIÓN )
BUSCAR → IDENTIFICADOR . find( EXPRESIÓN )
CONVERSIONES → EXPRESIÓN . to_tipo


