# COMPONENTES BÁSICOS
TIPO_DATO         → full | half | bin | crs | chain
IDENTIFICADOR     → [a-zA-Z_][a-zA-Z0-9_]*
LITERAL           → número          | cadena
OP                → + | - | * | / | == | != | < | > | <= | >= | && | ||

# PROGRAMA
PROGRAMA          → class IDENTIFICADOR { SENTENCIAS }

# BLOQUES Y SENTENCIAS
BLOQUE            → { SENTENCIAS }
SENTENCIAS        → SENTENCIA SENTENCIAS | ε
SENTENCIA         → DECLARACION
                  | ASIGNACION ;
                  | PUTS ;
                  | CONDICION
                  | BUCLE

# DECLARACIONES Y ASIGNACIONES
DECLARACION       → TIPO_DATO IDENTIFICADOR = EXPRESION ;
ASIGNACION        → IDENTIFICADOR = EXPRESION

# LECTURA/ESCRITURA
PUTS              → puts ( ARGUMENTO )
ARGUMENTO         → LITERAL | IDENTIFICADOR | EXPRESION

# EXPRESIONES
EXPRESION         → TÉRMINO
                  | EXPRESION OP EXPRESION
TÉRMINO           → IDENTIFICADOR
                  | LITERAL
                  | ( EXPRESION )

# ESTRUCTURAS DE CONTROL
CONDICION         → if ( EXPRESION ) BLOQUE ELSE_OPCIONAL
ELSE_OPCIONAL     → else BLOQUE | ε

BUCLE             → while ( EXPRESION ) BLOQUE
                  | for ( INICIALIZACION_FOR ; EXPRESION ; INCREMENTO_FOR ) BLOQUE

INICIALIZACION_FOR → IDENTIFICADOR = EXPRESION
INCREMENTO_FOR    → IDENTIFICADOR = EXPRESION
