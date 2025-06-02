import tkinter as tk
from tkinter import scrolledtext
import re
import os
import time

# --------------------- CONFIGURACIÓN ---------------------
SIMBOLOS_VALIDOS = ['+', '-', '*', '/', '=', '==', '!=', '<=', '>=', '<', '>', '(', ')', '{', '}', '[', ']', ';', ':', ',', '.', '&&', '||', '!']
PALABRAS_RESERVADAS = [
    "class", "init", "end", "if", "else", "while", "for", "switch", "case", "default",
    "puts", "full", "half", "bin", "crs", "chain"
]
TABLA_SIMBOLOS = "Tabla_de_simbolos.txt"
HASH_TABLA = {}

# --------------------- HASH DE PALABRAS RESERVADAS (como tabla de dispersión eficiente) ---------------------
def hash_simple(palabra):
    h = 0
    for i, c in enumerate(palabra):
        h ^= (ord(c) + i * 31)  # combinación simple con XOR y desplazamiento
        h *= 17  # constante para mezclar más
        h &= 0xFFFFFFFF  # aseguramos 32 bits para evitar overflow
    return f"{h:08x}"  # convertimos a hex con relleno a 8 caracteres

def construir_hash():
    global HASH_TABLA
    HASH_TABLA = {palabra: hash_simple(palabra) for palabra in PALABRAS_RESERVADAS}
    with open("tabla_hash.txt", "w") as archivo:
        archivo.write("Tabla hash de palabras reservadas:\n\n")
        for palabra, hash_val in HASH_TABLA.items():
            archivo.write(f"{palabra}: {hash_val}\n")

def mostrar_tabla_hash():
    construir_hash()
    ventana_hash = tk.Toplevel(root)
    ventana_hash.title("Tabla Hash de Palabras Reservadas")
    ventana_hash.geometry("400x400")

    texto_hash = scrolledtext.ScrolledText(ventana_hash, font=("Courier", 11))
    texto_hash.pack(expand=True, fill="both")

    texto_hash.insert(tk.END, "Palabra reservada : Hash\n\n")
    for palabra, hash_val in HASH_TABLA.items():
        texto_hash.insert(tk.END, f"{palabra:<20}: {hash_val}\n")
    texto_hash.config(state=tk.DISABLED)

# --------------------- TABLA DE SÍMBOLOS ---------------------
if not os.path.exists(TABLA_SIMBOLOS):
    with open(TABLA_SIMBOLOS, "w") as archivo:
        for palabra in PALABRAS_RESERVADAS:
            archivo.write(f"{palabra}\n")

def limpiar_tabla():
    with open(TABLA_SIMBOLOS, "w") as archivo:
        for palabra in PALABRAS_RESERVADAS:
            archivo.write(f"{palabra}\n")

def agregar_a_tabla_simbolos(token):
    with open(TABLA_SIMBOLOS, "r+") as archivo:
        contenido = archivo.read().splitlines()
        if token not in contenido:
            archivo.write(f"{token}\n")

# --------------------- AFDs ---------------------
def es_identificador(token):
    return re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", token) is not None

def es_numero(token):
    return re.fullmatch(r"\d+(\.\d+)?", token) is not None

# --------------------- ANÁLISIS SINTÁCTICO ---------------------
def analizar_sintaxis(tokens):
    errores = []
    i = 0
    longitud = len(tokens)
    contador_llaves = 0

<<<<<<< Updated upstream
    while i < longitud:
=======
    # Validación estructura inicial (existente)
    if longitud < 4:
        errores.append("Error: El código debe iniciar con 'class <nombre> {' y terminar con '}'.")
        return errores

    if tokens[0] != "class":
        errores.append("Error: El código debe comenzar con la palabra reservada 'class'.")
        return errores

    if not es_identificador(tokens[1]):
        errores.append("Error: Se esperaba un identificador después de 'class'.")
        return errores

    if tokens[2] != "{":
        errores.append("Error: Se esperaba una llave de apertura '{' después del nombre de la clase.")
        return errores

    if tokens[-1] != "}":
        errores.append("Error: El código debe finalizar con una llave de cierre '}'.")
        return errores

    contador_llaves = 1
    i = 3  
    
    #-------------------REESTRUCTURACIÓN PARA RECURSIVIDAD-----------------
    # Función para validar expresiones (existente)
    def analizar_sentencia(indice):
        """Distribuye a las funciones específicas (if, for, puts, etc.)."""
        token = tokens[indice]
        if token == "if":
            return analizar_if(indice)
        elif token == "while":
            return analizar_while(indice)
        elif token == "for":
            return analizar_for(indice)
        elif token in ["int", "float", "string", "bool", "void"]:
            return analizar_metodo(indice)
        elif token == "puts":
            return analizar_puts(indice)
    # ... más casos
        else:
            errores.append(f"Sentencia no reconocida: '{token}'")
            return indice, False
        
    def analizar_metodo(indice):
        """Valida la estructura de un método y su cuerpo recursivamente."""
    # 1. Validar tipo de retorno
        if tokens[indice] not in ["int", "float", "string", "bool", "void"]:
            errores.append(f"Error: Tipo de retorno inválido '{tokens[indice]}'")
            return indice, False
    # 2. Validar nombre del método
        if indice + 1 >= len(tokens) or not es_identificador(tokens[indice + 1]):
            errores.append(f"Error: Nombre de método inválido '{tokens[indice + 1]}'")
            return indice, False
    # 3. Validar apertura '('
        if indice + 2 >= len(tokens) or tokens[indice + 2] != "(":
            errores.append("Error: Falta '(' después del nombre del método")
            return indice, False
    # 4. Validar parámetros (pueden estar vacíos)
        indice_parametros = indice + 3
        indice_parametros, ok = analizar_parametros(indice_parametros)
        if not ok:
            return indice_parametros, False
    # 5. Validar cierre ')'
        if tokens[indice_parametros] != ")":
            errores.append("Error: Falta ')' después de los parámetros")
            return indice_parametros, False
    # 6. Validar bloque del método (recursivo)
        indice_bloque = indice_parametros + 1
        indice_bloque, ok = analizar_bloque(indice_bloque)
        return indice_bloque, ok

    def analizar_parametros(indice):
        """Valida la lista de parámetros: (TIPO_DATO IDENTIFICADOR, ...)"""
        while indice < len(tokens) and tokens[indice] != ")":
        # Validar tipo del parámetro
            if tokens[indice] not in ["int", "float", "string", "bool"]:
                errores.append(f"Error: Tipo de parámetro inválido '{tokens[indice]}'")
                return indice, False
        
        # Validar nombre del parámetro
            if indice + 1 >= len(tokens) or not es_identificador(tokens[indice + 1]):
                errores.append(f"Error: Nombre de parámetro inválido '{tokens[indice + 1]}'")
                return indice + 1, False
        
            indice += 2  # Saltar tipo y nombre
        
        # Verificar si hay más parámetros
            if indice < len(tokens) and tokens[indice] == ",":
                indice += 1
                if indice >= len(tokens) or tokens[indice] in [")", ","]:
                    errores.append("Error: Falta parámetro después de ','")
                    return indice, False
                
        return indice, True

    def analizar_bloque(indice):
        """Valida un bloque {} y las sentencias dentro de él. Estructura: { SENTENCIAS } → SENTENCIAS puede ser vacío o múltiples sentencias."""
        if indice >= len(tokens) or tokens[indice] != "{":
            errores.append("Error: Se esperaba '{' para iniciar un bloque")
            return indice, False

        indice += 1  # Saltar '{'
        llaves_abiertas = 1

        while indice < len(tokens) and llaves_abiertas > 0:
            if tokens[indice] == "}":
                llaves_abiertas -= 1
                if llaves_abiertas == 0:
                    break  # Bloque cerrado correctamente
            elif tokens[indice] == "{":
                llaves_abiertas += 1  # Bloque anidado

            # Validar cada sentencia dentro del bloque (recursivo)
            indice, ok = analizar_sentencia(indice)
            if not ok:
                return indice, False

        if llaves_abiertas != 0:
            errores.append("Error: Falta '}' para cerrar el bloque")
            return indice, False
        
        return indice + 1, True  # Saltar '}'
    
    def analizar_sentencia(indice):
        """Decide qué tipo de sentencia es y redirige a la función correspondiente."""
        token = tokens[indice]

        # 1. Declaración de variable (ej: int x = 5;)
        if token in ["int", "float", "string", "bool"]:
            return analizar_declaracion(indice)

        # 2. Estructuras de control
        elif token == "if":
            return analizar_if(indice)
        elif token == "while":
            return analizar_while(indice)
        elif token == "for":
            return analizar_for(indice)

        # 3. Llamadas a función o asignaciones (ej: puts("hola"); o x = 10;)
        elif es_identificador(token) and indice + 1 < len(tokens) and tokens[indice + 1] == "=":
            return analizar_asignacion(indice)
        elif token == "puts":
            return analizar_puts(indice)

        # 4. Bloques vacíos o llaves adicionales
        elif token == "}" or token == "{":
            return indice + 1, True  # Ignorar (ya se maneja en analizar_bloque)
        else:
            errores.append(f"Error: Sentencia no reconocida '{token}'")
        return indice, False
    
    def analizar_expresion(indice):
        """Valida expresiones como 'x + 5', '(a == b)', etc."""
        while indice < len(tokens) and tokens[indice] not in [";", ")", "}"]:
            token = tokens[indice]
            if token == "(":
                indice, ok = analizar_expresion(indice + 1)
                if not ok or tokens[indice] != ")":
                    return indice, False
                indice +=1
            elif not (es_identificador(token) or es_numero(token) or token in SIMBOLOS_VALIDOS):
                errores.append(f"Erro: Token inválido en expresión: '{token}'")
                return indice, False
            else:
                indice += 1
        return indice, True
    
    def analizar_if(indice):
        """Valida if (condición) { bloque } [else { bloque }]"""
        if tokens[indice] != "if":
            return indice, False
        indice += 1
        # Validar condición
        if tokens[indice] != "(":
            errores.append("Error: Falta '(' después de 'if'")
            return indice, False
        indice, ok = analizar_expresion(indice + 1)
        if not ok or tokens[indice] != ")":
            errores.append("Error: Condición inválida o falta ')'")
            return indice, False
        indice += 1
        # Validar bloque
        indice, ok = analizar_bloque(indice)
        if not ok:
            return indice, False
        # Validar else (opcional)
        if indice < len(tokens) and tokens[indice] == "else":
            indice += 1
            indice, ok = analizar_bloque(indice)
        return indice, ok
#-------------------------------------------------------------------------
    
    # Función para validar expresiones (existente)
    def validar_expresion_desde(indice):
        if indice >= longitud or tokens[indice] != "(":
            errores.append("Error: Se esperaba '(' después de 'if'.")
            return indice, False
        indice += 1
        while indice < longitud and tokens[indice] != ")":
            if not (es_identificador(tokens[indice]) or es_numero(tokens[indice]) or tokens[indice] in SIMBOLOS_VALIDOS):
                errores.append(f"Expresión inválida en condición if: {tokens[indice]}")
                return indice, False
            indice += 1
        if indice == longitud or tokens[indice] != ")":
            errores.append("Error: Falta ')' al final de la condición if.")
            return indice, False
        return indice + 1, True
    
    # Función para validar bloques (existente)
    def validar_bloque_desde(indice):
        if indice >= longitud or tokens[indice] != "{":
            errores.append("Error: Se esperaba '{' para iniciar un bloque.")
            return indice, False
        indice += 1
        llaves_abiertas = 1
        while indice < longitud and llaves_abiertas > 0:
            if tokens[indice] == "{":
                llaves_abiertas += 1
            elif tokens[indice] == "}":
                llaves_abiertas -= 1
            indice += 1
        if llaves_abiertas != 0:
            errores.append("Error: Llave '{' sin cerrar en bloque.")
            return indice, False
        return indice, True

    #Función para validar métodos (nueva)
    def validar_metodo_desde(indice):
        if indice >= longitud:
            errores.append("Error: Inesperado final de código al esperar método.")
            return indice, False
        #1. Validar tipo de datos del método
        if tokens[indice] not in ["int","float", "string", "bool", "void"]:
            errores.append(f"Error: Tipo de dato no válido para método: '{tokens[indice]}'")
            return indice, False
    
        #2. Validar identificador del método
        if indice +1 >= longitud or not es_identificador(tokens[indice + 1]):
            errores.append(f"Error: Se esperaba un identificador después del tipo '{tokens[indice]}'")
            return indice, False
    
        #3. Validar paréntesis de apertura para parámetros
        if indice + 2 >= longitud or tokens[indice + 2] != "(":
            errores.append("Error: Se esperaba '(' después del nombre del método")
            return indice, False
        indice +=3 #Avanzamos al inicio de los parámetros

        #4. Validar parámetros (pueden estar vacios)
        while indice < longitud and tokens[indice] != ")":
            #Verificar tipo del parámetro
            if tokens[indice] not in ["int", "float", "string", "bool"]:
                errores.append(f"Error: Tipo de parámetro no válido: '{tokens[indice]}'")
                return indice, False
            #verificar indentificador del parámetro
            if indice + 1 >= longitud or not es_identificador(tokens[indice + 1]):
                errores.append(f"Error: Falta identificador para parámetro de tipo '{tokens[indice]}'")
                return indice, False
            indice +=2 #Avanzar al siguiente token

            if indice < longitud and tokens[indice] == ",":
                indice +=1
                if indice >= longitud or tokens[indice] in [")",","]:
                    errores.append("Error: Se esperaba otro parámetro después de ','")
                    return indice, False
        #5. Validar paréntesis de cierre
        if indice >= longitud or tokens[indice] != ")":
            errores.append("Error: Falta ')' al final de los parámetros del método")
            return indice, False
        indice +=1 #Avanzar al bloque del método

        #6. Validar bloque del método
        indice, ok = validar_bloque_desde(indice)
        if not ok:
            return indice, False

        return indice, True
    
    # Nueva función para validar estructura del for
    def validar_for_desde(indice):
        if indice + 1 >= longitud or tokens[indice + 1] != "(":
            errores.append("Error: Se esperaba '(' después de 'for'.")
            return indice, False
        
        indice += 2  # Saltar 'for' y '('
        
        # Validar inicialización (debe ser una asignación)
        if indice + 3 >= longitud or tokens[indice + 1] != "=":
            errores.append("Error: Inicialización del 'for' debe ser una asignación (ej: i = 0).")
            return indice, False
        
        indice += 3  # Saltar variable, '=' y valor
        
        if indice >= longitud or tokens[indice] != ";":
            errores.append("Error: Falta ';' después de la inicialización del 'for'.")
            return indice, False
        
        indice += 1  # Saltar ';'
        
        inicio_condicion = indice
        while indice < longitud and tokens[indice] != ";":
            indice += 1
        
        if indice >= longitud:
            errores.append("Error: Falta ';' después de la condición del 'for'.")
            return indice, False
        
        condicion = tokens[inicio_condicion:indice]
        if not condicion:
            errores.append("Error: Falta condición en el 'for'.")
            return indice, False
        
        indice += 1  
        inicio_incremento = indice
        while indice < longitud and tokens[indice] != ")":
            indice += 1
        
        if indice >= longitud:
            errores.append("Error: Falta ')' al final del 'for'.")
            return indice, False
        
        incremento = tokens[inicio_incremento:indice]
        if not incremento:
            errores.append("Error: Falta incremento en el 'for'.")
            return indice, False
        
        if len(incremento) < 3 or incremento[1] != "=":
            errores.append("Error: Incremento del 'for' debe ser una asignación (ej: i = i + 1).")
            return indice, False
        
        indice += 1 
        indice, ok = validar_bloque_desde(indice)
        if not ok:
            return indice, False
        
        return indice, True

    while i < longitud - 1:
>>>>>>> Stashed changes
        token = tokens[i]
        if token in ["full", "half", "bin", "crs", "chain"]:
            if i+1 < longitud and es_identificador(tokens[i+1]):
                if i+2 < longitud and tokens[i+2] == "=":
                    j = i+3
                    while j < longitud and tokens[j] != ";":
                        if not (es_identificador(tokens[j]) or es_numero(tokens[j]) or tokens[j] in SIMBOLOS_VALIDOS):
                            errores.append(f"Expresión inválida en asignación: {tokens[j]}")
                            break
                        j += 1
                    if j < longitud and tokens[j] == ";":
                        i = j + 1
                        continue
                    else:
                        errores.append("Falta ';' al final de la declaración.")
                        i = j + 1
                        continue
                elif i+2 < longitud and tokens[i+2] == ";":
                    i += 3
                    continue
                else:
                    errores.append("Falta ';' al final de la declaración.")
                    i += 3
                    continue
<<<<<<< Updated upstream
=======
            continue

        elif token == "for":
            i, ok = validar_for_desde(i)
            if not ok:
                continue
            continue

        elif token in ["full", "half", "bin", "crs", "chain"]:
            pass

        elif token in ["int", "float", "string", "bool", "void"]:
        # Verificar si es una declaración de método (no solo una declaración de variable)
            if i + 2 < longitud and tokens[i+2]=="(":
                i, ok = validar_metodo_desde(i)
                if not ok:
                    continue
                continue
            else:
                #Declaración de variables normal,  manejar acorde a la lógica actual
                pass

        elif token == "puts":
            if i + 4 < longitud and tokens[i+1] == "(" and tokens[i+3] == ")" and tokens[i+4] == ";":
                i += 5
                continue
>>>>>>> Stashed changes
            else:
                errores.append("Nombre de variable no válido.")
                i += 2
                continue
        elif token == "puts":
            if i+1 < longitud and tokens[i+1] == "(":
                j = i+2
                while j < longitud and tokens[j] != ")":
                    if tokens[j] not in [","] + SIMBOLOS_VALIDOS and not (es_identificador(tokens[j]) or es_numero(tokens[j])):
                        errores.append(f"Argumento inválido en puts: {tokens[j]}")
                        break
                    j += 1
                if j+1 < longitud and tokens[j] == ")" and tokens[j+1] == ";":
                    i = j + 2
                    continue
                else:
                    errores.append("Error de sintaxis en puts.")
                    i = j + 2
                    continue
        elif token == "{":
            contador_llaves += 1
        elif token == "}":
            if contador_llaves > 0:
                contador_llaves -= 1
            else:
                errores.append("Error: llave de cierre '}' sin llave de apertura '{'.")
        elif token in ["if", "while", "for", "switch"]:
            pass
        i += 1
    if contador_llaves > 0:
        errores.append(f"Error: {contador_llaves} llave(s) de apertura '{{' sin cerrar '}}'.")
    return errores

# --------------------- INTERPRETACIÓN ---------------------
def interpretar(tokens):
    salida = []
    memoria = {}
    i = 0
    longitud = len(tokens)

    while i < longitud:
        token = tokens[i]
        if token in ["full", "half", "bin", "crs", "chain"]:
            if i+1 < longitud and es_identificador(tokens[i+1]):
                var = tokens[i+1]
                if i+2 < longitud and tokens[i+2] == "=":
                    j = i+3
                    expr = ""
                    while j < longitud and tokens[j] != ";":
                        expr += tokens[j]
                        j += 1
                    try:
                        valor = eval(expr, {}, memoria)
                        memoria[var] = valor
                    except Exception:
                        salida.append(f"[Error ejecución] Asignación inválida: {expr}")
                    i = j + 1
                    continue
                elif i+2 < longitud and tokens[i+2] == ";":
                    memoria[var] = None
                    i += 3
                    continue
        elif token == "puts":
            if i+1 < longitud and tokens[i+1] == "(":
                j = i+2
                expr = ""
                while j < longitud and tokens[j] != ")":
                    expr += tokens[j] if tokens[j] != "," else " "
                    j += 1
                try:
                    valores = [str(memoria.get(e, e)) for e in expr.strip().split()]
                    salida.append(" ".join(valores))
                except Exception as e:
                    salida.append(f"[Error ejecución] Error en puts: {e}")
                i = j + 2
                continue
        i += 1
    return salida

# --------------------- COMPILACIÓN ---------------------
def compilar():
    tokens = [...]
    inicio = time.time()

    texto = editor_text.get("1.0", tk.END)
    token_pattern = r'==|!=|<=|>=|&&|\|\||[+\-*/=<>!;:{}()\[\],\.]|\d+\.\d+|\d+|[a-zA-Z_]\w*'
    tokens = re.findall(token_pattern, texto)

    resultado_text.config(state=tk.NORMAL)
    resultado_text.delete("1.0", tk.END)
    errores_text.config(state=tk.NORMAL)
    errores_text.delete("1.0", tk.END)

    resultado_text.insert(tk.END, "Tokens encontrados:\n\n")
    for token in tokens:
        resultado_text.insert(tk.END, f"{token}\n")
        if es_identificador(token) and token not in HASH_TABLA:
            agregar_a_tabla_simbolos(token)
        elif es_numero(token):
            agregar_a_tabla_simbolos(token)

    construir_hash()

    errores_sintacticos = analizar_sintaxis(tokens)
    if not errores_sintacticos:
        salida = interpretar(tokens)

    elif errores_sintacticos:
        errores_text.insert(tk.END, "Errores encontrados:\n\n")
        for err in errores_sintacticos:
            errores_text.insert(tk.END, f"Error sintáctico: {err}\n")
    else:
        salida = interpretar(tokens)
        errores_text.insert(tk.END, "Resultado de ejecución:\n\n")
        for linea in salida:
            errores_text.insert(tk.END, f"{linea}\n")
    
    fin = time.time()
    duracion = fin - inicio
    errores_text.insert(tk.END, f"\nTiempo de compilación: {duracion:.4f} segundos")

    resultado_text.config(state=tk.DISABLED)
    errores_text.config(state=tk.DISABLED)

# --------------------- RESALTADO DE PALABRAS RESERVADAS ---------------------
def resaltar_palabras(event=None):
    editor_text.tag_remove("reservada", "1.0", tk.END)
    texto = editor_text.get("1.0", tk.END)
    for palabra in PALABRAS_RESERVADAS:
        for match in re.finditer(rf'\b{palabra}\b', texto):
            inicio = f"1.0 + {match.start()} chars"
            final = f"1.0 + {match.end()} chars"
            editor_text.tag_add("reservada", inicio, final)
    editor_text.tag_config("reservada", foreground="green")

# --------------------- MODO OSCURO ---------------------
modo_oscuro = False
def alternar_tema():
    global modo_oscuro
    modo_oscuro = not modo_oscuro
    if modo_oscuro:
        root.tk_setPalette(background="#2E2E2E", foreground="white")
        editor_text.config(bg="#1E1E1E", fg="white", insertbackground="white")
        resultado_text.config(bg="#1E1E1E", fg="white")
        errores_text.config(bg="#1E1E1E", fg="red")
        btn_compilar.config(bg="#444", fg="white")
        btn_tema.config(bg="#444", fg="white")
        btn_limpiar.config(bg="#444", fg="white")
    else:
        root.tk_setPalette(background="white", foreground="black")
        editor_text.config(bg="white", fg="black", insertbackground="black")
        resultado_text.config(bg="white", fg="black")
        errores_text.config(bg="white", fg="red")
        btn_compilar.config(bg="lightgray", fg="black")
        btn_tema.config(bg="lightgray", fg="black")
        btn_limpiar.config(bg="lightgray", fg="black")

# --------------------- INTERFAZ ---------------------
root = tk.Tk()
root.title("Interfaz de Compilador con Tiempos")
root.geometry("900x800")

editor_text = scrolledtext.ScrolledText(root, height=10, width=100, font=("Courier", 12))
editor_text.pack(pady=10)
editor_text.bind("<KeyRelease>", resaltar_palabras)

btn_compilar = tk.Button(root, text="Analizar / Compilar", command=compilar)
btn_compilar.pack()

btn_tema = tk.Button(root, text="Modo Noche", command=alternar_tema)
btn_tema.pack()

btn_limpiar = tk.Button(root, text="Limpiar Tabla de Símbolos", command=limpiar_tabla)
btn_limpiar.pack()

btn_hash = tk.Button(root, text="Ver Tabla Hash", command=mostrar_tabla_hash)
btn_hash.pack()

resultado_text = scrolledtext.ScrolledText(root, height=10, width=100, font=("Courier", 12), state=tk.DISABLED)
resultado_text.pack(pady=10)

errores_text = scrolledtext.ScrolledText(root, height=7, width=100, font=("Courier", 12), fg="red", state=tk.DISABLED)
errores_text.pack(pady=10)

root.mainloop()
