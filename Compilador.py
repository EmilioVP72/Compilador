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
        h ^= (ord(c) + i * 31)  
        h *= 17  
        h &= 0xFFFFFFFF 
    return f"{h:08x}"  

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
        
        # Validar que haya punto y coma después de inicialización
        if indice >= longitud or tokens[indice] != ";":
            errores.append("Error: Falta ';' después de la inicialización del 'for'.")
            return indice, False
        
        indice += 1  # Saltar ';'
        
        # Validar condición (debe ser una expresión booleana)
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
        
        indice += 1  # Saltar ';'
        
        # Validar incremento (debe ser una asignación o operación)
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
        
        # Validar que el incremento sea una asignación (i = i + 1) o operación unaria (i++)
        if len(incremento) < 3 or incremento[1] != "=":
            errores.append("Error: Incremento del 'for' debe ser una asignación (ej: i = i + 1).")
            return indice, False
        
        indice += 1  # Saltar ')'
        
        # Validar el bloque de código
        indice, ok = validar_bloque_desde(indice)
        if not ok:
            return indice, False
        
        return indice, True

    while i < longitud - 1:
        token = tokens[i]

        if token == "if":
            i, ok = validar_expresion_desde(i + 1)
            if not ok:
                continue
            i, ok = validar_bloque_desde(i)
            if not ok:
                continue
            if i < longitud and tokens[i] == "else":
                i += 1
                i, ok = validar_bloque_desde(i)
                if not ok:
                    continue
            continue

        # Nueva validación para el ciclo for
        elif token == "for":
            i, ok = validar_for_desde(i)
            if not ok:
                continue
            continue

        elif token in ["full", "half", "bin", "crs", "chain"]:
            pass

        elif token == "puts":
            if i + 4 < longitud and tokens[i+1] == "(" and tokens[i+3] == ")" and tokens[i+4] == ";":
                i += 5
                continue
            else:
                errores.append("Error sintáctico: 'puts' debe tener formato puts('...'); con ';' obligatorio")
                i += 1
                continue

        elif token == "{":
            contador_llaves += 1
        elif token == "}":
            if contador_llaves > 1:
                contador_llaves -= 1
            else:
                errores.append("Error: llave de cierre '}' sin llave de apertura '{'.")
        i += 1

    if contador_llaves > 1:
        errores.append(f"Error: {contador_llaves - 1} llave(s) de apertura '{{' sin cerrar '}}'.")

    return errores

# --------------------- INTERPRETACIÓN ---------------------
def interpretar(tokens):
    salida = []
    memoria = {}
    i = 0
    longitud = len(tokens)

    def evaluar_expresion(expr_tokens):
        expr = "".join(expr_tokens)
        try:
            return eval(expr, {}, memoria)
        except Exception:
            return False

    def ejecutar_bloque(inicio):
        j = inicio
        resultado = []
        if tokens[j] != '{':
            return j, resultado  

        j += 1
        bloque_tokens = []
        llaves = 1
        while j < longitud and llaves > 0:
            if tokens[j] == '{':
                llaves += 1
            elif tokens[j] == '}':
                llaves -= 1
                if llaves == 0:
                    break
            bloque_tokens.append(tokens[j])
            j += 1

        return j + 1, bloque_tokens

    while i < longitud:
        token = tokens[i]

        if token in ["full", "half", "bin", "crs", "chain"]:
            if i + 2 < longitud and tokens[i + 2] == "=":
                var = tokens[i + 1]
                j = i + 3
                expr_tokens = []
                while j < longitud and tokens[j] != ";":
                    expr_tokens.append(tokens[j])
                    j += 1
                val = evaluar_expresion(expr_tokens)
                memoria[var] = val
                i = j + 1
                continue
            else:
                i += 3
                continue

        elif token == "if":
            if i + 1 < longitud and tokens[i + 1] == "(":
                j = i + 2
                cond_tokens = []
                paren_count = 1
                while j < longitud and paren_count > 0:
                    if tokens[j] == "(":
                        paren_count += 1
                    elif tokens[j] == ")":
                        paren_count -= 1
                        if paren_count == 0:
                            break
                    if paren_count > 0:
                        cond_tokens.append(tokens[j])
                    j += 1
                condicion = evaluar_expresion(cond_tokens)
                j += 1
                j, bloque_true = ejecutar_bloque(j)
                bloque_false = []
                if j < longitud and tokens[j] == "else":
                    j += 1
                    j, bloque_false = ejecutar_bloque(j)
                if condicion:
                    for k in range(len(bloque_true)):
                        if bloque_true[k] == "puts" and k + 4 < len(bloque_true):
                            val = bloque_true[k + 2].strip("'\"")
                            salida.append(val)
                            k += 4
                else:
                    for k in range(len(bloque_false)):
                        if bloque_false[k] == "puts" and k + 4 < len(bloque_false):
                            val = bloque_false[k + 2].strip("'\"")
                            salida.append(val)
                            k += 4
                i = j
                continue
            else:
                i += 1

        elif token == "for":
            if i + 1 < longitud and tokens[i + 1] == "(":
                j = i + 2
                var = tokens[j]
                if tokens[j + 1] != "=":
                    i += 1
                    continue
                valor_inicial = evaluar_expresion([tokens[j + 2]])
                memoria[var] = valor_inicial

                j += 4  # saltar a condición
                condicion_tokens = []
                while j < longitud and tokens[j] != ";":
                    condicion_tokens.append(tokens[j])
                    j += 1
                j += 1  # salto a incremento

                incremento_tokens = []
                while j < longitud and tokens[j] != ")":
                    incremento_tokens.append(tokens[j])
                    j += 1
                j += 1  # salto a bloque

                j, bloque_tokens = ejecutar_bloque(j)
                while evaluar_expresion(condicion_tokens):
                    k = 0
                    while k < len(bloque_tokens):
                        t = bloque_tokens[k]
                        if t == "puts" and k + 4 < len(bloque_tokens) and bloque_tokens[k + 1] == "(" and bloque_tokens[k + 3] == ")" and bloque_tokens[k + 4] == ";":
                            val = bloque_tokens[k + 2].strip("'\"")
                            salida.append(val)
                            k += 5
                        else:
                            k += 1
                    if len(incremento_tokens) >= 3 and incremento_tokens[1] == "=":
                        var = incremento_tokens[0]
                        val = evaluar_expresion(incremento_tokens[2:])
                        memoria[var] = val
                i = j
                continue

        elif token == "puts":
            if i + 4 < longitud and tokens[i + 1] == "(" and tokens[i + 3] == ")" and tokens[i + 4] == ";":
                val = tokens[i + 2].strip("'\"")
                salida.append(val)
                i += 5
                continue
            else:
                i += 1

        else:
            i += 1

    return salida

# --------------------- COMPILACIÓN ---------------------
def compilar():
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
    if errores_sintacticos:
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
