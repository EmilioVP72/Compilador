import tkinter as tk
from tkinter import scrolledtext, filedialog
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
ARCHIVO_BIN = "tabla_simbolos.bin"
TAM_SLOT = 32
NUM_SLOTS = 256  

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
def analizar_sintaxis_por_linea(texto_fuente):
    lineas = texto_fuente.strip().splitlines()
    errores = []

    token_pattern = r"'[^']*'|\"[^\"]*\"|==|!=|<=|>=|&&|\|\||[+\-*/=<>!;:{}()\[\],\.]|\d+\.\d+|\d+|[a-zA-Z_]\w*"
    tokens_todo = re.findall(token_pattern, texto_fuente)

    if len(tokens_todo) < 4:
        errores.append("El código debe comenzar con 'class <Nombre> {' y finalizar con '}'.")
        return errores

    if tokens_todo[0] != "class":
        errores.append("El código debe comenzar con la palabra reservada 'class'.")
    elif not es_identificador(tokens_todo[1]):
        errores.append("Se esperaba un identificador después de 'class'.")
    elif tokens_todo[2] != "{":
        errores.append("Se esperaba '{' después del nombre de la clase.")
    if tokens_todo[-1] != "}":
        errores.append("El código debe finalizar con una llave de cierre '}'.")

    for num_linea, linea in enumerate(lineas, start=1):
        tokens = re.findall(token_pattern, linea)
        if not tokens:
            continue
        errores.extend(analizar_linea(tokens, num_linea))

    # Validación de balance de llaves
    apertura = texto_fuente.count("{")
    cierre = texto_fuente.count("}")
    if apertura > cierre:
        errores.append(f"Hay {apertura - cierre} llave(s) '{{' sin cerrar con '}}'.")
    elif cierre > apertura:
        errores.append(f"Hay {cierre - apertura} llave(s) '}}' sin apertura '{{'.")

    return errores

def analizar_linea(tokens, num_linea):
    errores = []

    if tokens[0] in ["full", "half", "bin", "crs", "chain"]:
        if len(tokens) < 5:
            errores.append(f"Línea {num_linea}: Instrucción incompleta.")
        elif not es_identificador(tokens[1]):
            errores.append(f"Línea {num_linea}: Identificador inválido.")
        elif tokens[2] != "=":
            errores.append(f"Línea {num_linea}: Se esperaba '=' después del identificador.")
        elif tokens[-1] != ";":
            errores.append(f"Línea {num_linea}: Se esperaba ';' al final de la declaración.")

    elif tokens[0] == "puts":
        if len(tokens) < 5:
            errores.append(f"Línea {num_linea}: Instrucción 'puts' incompleta.")
        elif tokens[1] != "(":
            errores.append(f"Línea {num_linea}: Se esperaba '(' después de 'puts'.")
        elif tokens[-2] != ")":
            errores.append(f"Línea {num_linea}: Se esperaba ')' antes del ';'.")
        elif tokens[-1] != ";":
            errores.append(f"Línea {num_linea}: Se esperaba ';' al final de 'puts'.")
        else:
            argumento = tokens[2]
            if argumento.startswith("'") and not argumento.endswith("'"):
                errores.append(f"Línea {num_linea}: Falta comilla de cierre simple en argumento de 'puts'.")
            elif argumento.startswith('\"') and not argumento.endswith('\"'):
                errores.append(f"Línea {num_linea}: Falta comilla de cierre doble en argumento de 'puts'.")

    elif tokens[0] == "if":
        if "(" not in tokens or ")" not in tokens:
            errores.append(f"Línea {num_linea}: Falta paréntesis en condición de 'if'.")
        else:
            try:
                i1 = tokens.index("(")
                i2 = tokens.index(")", i1)
                cond = tokens[i1 + 1:i2]
                if len(cond) < 3:
                    errores.append(f"Línea {num_linea}: Condición 'if' demasiado corta o incompleta.")
                elif not any(op in cond for op in ["<", ">", "==", "!=", "<=", ">="]):
                    errores.append(f"Línea {num_linea}: Falta operador lógico en condición de 'if'.")
            except ValueError:
                errores.append(f"Línea {num_linea}: Estructura de condición 'if' mal formada.")

    elif tokens[0] == "while":
        if "(" not in tokens or ")" not in tokens:
            errores.append(f"Línea {num_linea}: Falta paréntesis en condición de 'while'.")
        else:
            try:
                i1 = tokens.index("(")
                i2 = tokens.index(")", i1)
                cond = tokens[i1 + 1:i2]
                if len(cond) < 3:
                    errores.append(f"Línea {num_linea}: Condición 'while' demasiado corta o incompleta.")
                elif not any(op in cond for op in ["<", ">", "==", "!=", "<=", ">="]):
                    errores.append(f"Línea {num_linea}: Falta operador lógico en condición de 'while'.")
            except ValueError:
                errores.append(f"Línea {num_linea}: Estructura de condición 'while' mal formada.")

    elif tokens[0] == "for":
        if "(" not in tokens or ")" not in tokens:
            errores.append(f"Línea {num_linea}: Falta paréntesis en 'for'.")
        else:
            try:
                i1 = tokens.index("(")
                i2 = tokens.index(";", i1)
                i3 = tokens.index(";", i2 + 1)
                i4 = tokens.index(")", i3)

                # Inicialización
                init = tokens[i1 + 1:i2]
                if len(init) < 3 or init[1] != "=":
                    errores.append(f"Línea {num_linea}: Asignación inválida en la inicialización del 'for'.")

                # Condición
                cond = tokens[i2 + 1:i3]
                if not any(op in cond for op in ["<", ">", "==", "!=", "<=", ">="]):
                    errores.append(f"Línea {num_linea}: Falta operador lógico en condición del 'for'.")

                # Incremento
                inc = tokens[i3 + 1:i4]
                if len(inc) < 3 or inc[1] != "=":
                    errores.append(f"Línea {num_linea}: Incremento inválido en 'for'. Se esperaba una asignación como i = i + 1.")

            except ValueError:
                errores.append(f"Línea {num_linea}: Estructura 'for' mal formada o incompleta.")

    elif tokens[0] == "else":
        if len(tokens) == 1:
            errores.append(f"Línea {num_linea}: Falta bloque para 'else'.")
        elif tokens[1] != "{":
            errores.append(f"Línea {num_linea}: Se esperaba '{{' después de 'else'.")

    elif "=" in tokens:
        if tokens[-1] != ";":
            errores.append(f"Línea {num_linea}: Se esperaba ';' al final de la asignación.")

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

        elif token == "while":
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
                j += 1  # después del ')'
                j, bloque_tokens = ejecutar_bloque(j)
                while evaluar_expresion(cond_tokens):
                    k = 0
                    while k < len(bloque_tokens):
                        t = bloque_tokens[k]
                        if t == "puts" and k + 4 < len(bloque_tokens) and bloque_tokens[k + 1] == "(" and bloque_tokens[k + 3] == ")" and bloque_tokens[k + 4] == ";":
                            contenido = bloque_tokens[k + 2]
                            if re.fullmatch(r"'[^']*'|\"[^\"]*\"", contenido):
                                val = contenido.strip("'\"")
                            elif contenido in memoria:
                                val = memoria[contenido]
                            elif es_numero(contenido):
                                val = contenido
                            else:
                                val = f"[{contenido} no definido]"
                            salida.append(str(val))
                            k += 5

                        elif t in memoria and k + 2 < len(bloque_tokens) and bloque_tokens[k + 1] == "=":
                            var = bloque_tokens[k]
                            expr_tokens = []
                            k += 2
                            while k < len(bloque_tokens) and bloque_tokens[k] != ";":
                                expr_tokens.append(bloque_tokens[k])
                                k += 1
                            val = evaluar_expresion(expr_tokens)
                            memoria[var] = val
                            k += 1
                        else:
                            k += 1
                i = j
                continue

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
                            contenido = bloque_tokens[k + 2]
                            if re.fullmatch(r"'[^']*'|\"[^\"]*\"", contenido):
                                val = contenido.strip("'\"")
                            elif contenido in memoria:
                                val = memoria[contenido]
                            elif es_numero(contenido):
                                val = contenido
                            else:
                                val = f"[{contenido} no definido]"
                            salida.append(str(val))
                            k += 5
                            
                        elif t in memoria and k + 2 < len(bloque_tokens) and bloque_tokens[k + 1] == "=":
                            var = bloque_tokens[k]
                            expr_tokens = []
                            k += 2
                            while k < len(bloque_tokens) and bloque_tokens[k] != ";":
                                expr_tokens.append(bloque_tokens[k])
                                k += 1
                            val = evaluar_expresion(expr_tokens)
                            memoria[var] = val
                            k += 1
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
                contenido = tokens[i + 2]
        # Si es texto entre comillas, imprimimos el literal
                if re.fullmatch(r"'[^']*'|\"[^\"]*\"", contenido):
                    val = contenido.strip("'\"")
        # Si es identificador definido, imprimimos su valor
                elif contenido in memoria:
                    val = memoria[contenido]
        # Si es número explícito
                elif es_numero(contenido):
                    val = contenido
                else:
                    val = f"[{contenido} no definido]"
                salida.append(str(val))
                i += 5
                continue

        else:
            i += 1

    return salida

def inicializar_archivo_binario():
    if not os.path.exists(ARCHIVO_BIN):
        with open(ARCHIVO_BIN, "wb") as f:
            f.write(b'\x00' * TAM_SLOT * NUM_SLOTS)

def hash_numerico(token):
    h = 0
    for i, c in enumerate(token):
        h ^= (ord(c) + i * 31)
        h *= 17
        h &= 0xFFFFFFFF
    return h % NUM_SLOTS

def guardar_token_binario(token):
    token = token.strip()
    if not token:
        return

    token_bytes = token.encode('utf-8')[:TAM_SLOT]
    token_bytes += b'\x00' * (TAM_SLOT - len(token_bytes))

    pos_inicial = hash_numerico(token)

    with open(ARCHIVO_BIN, "r+b") as f:
        for intento in range(NUM_SLOTS):
            pos = (pos_inicial + intento) % NUM_SLOTS
            f.seek(pos * TAM_SLOT)
            datos = f.read(TAM_SLOT)

            if datos.strip(b'\x00') == b'':
                f.seek(pos * TAM_SLOT)
                f.write(token_bytes)
                break
            elif datos.strip(b'\x00') == token_bytes.strip(b'\x00'):
                break  # Ya está
        else:
            print("¡Tabla de símbolos llena!")

def imprimir_tabla_binaria():
    print("Contenido de tabla_simbolos.bin:")
    with open(ARCHIVO_BIN, "rb") as f:
        for i in range(NUM_SLOTS):
            f.seek(i * TAM_SLOT)
            datos = f.read(TAM_SLOT)
            if datos.strip(b'\x00'):
                print(f"[{i:03}] {datos.decode('utf-8').strip()}")
# --------------------- COMPILACIÓN ---------------------
def compilar():
    inicio = time.time()

    texto = editor_text.get("1.0", tk.END)
    token_pattern = r"'[^']*'|\"[^\"]*\"|==|!=|<=|>=|&&|\|\||[+\-*/=<>!;:{}()\[\],\.]|\d+\.\d+|\d+|[a-zA-Z_]\w*"
    tokens = re.findall(token_pattern, texto)

    resultado_text.config(state=tk.NORMAL)
    resultado_text.delete("1.0", tk.END)
    errores_text.config(state=tk.NORMAL)
    errores_text.delete("1.0", tk.END)

    resultado_text.insert(tk.END, "Tokens encontrados:\n\n")
    for token in tokens:
        resultado_text.insert(tk.END, f"{token}\n")
        if es_identificador(token) and token not in HASH_TABLA:
            guardar_token_binario(token)
        elif es_numero(token):
            guardar_token_binario(token)

    construir_hash()

    # Análisis línea por línea
    errores_sintacticos = analizar_sintaxis_por_linea(texto)
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
    else:
        root.tk_setPalette(background="white", foreground="black")
        editor_text.config(bg="white", fg="black", insertbackground="black")
        resultado_text.config(bg="white", fg="black")
        errores_text.config(bg="white", fg="red")
        btn_compilar.config(bg="lightgray", fg="black")
        btn_tema.config(bg="lightgray", fg="black")

def mostrar_tabla_binaria():
    ventana_bin = tk.Toplevel(root)
    ventana_bin.title("Tabla de Símbolos (Binaria)")
    ventana_bin.geometry("400x500")

    texto_bin = scrolledtext.ScrolledText(ventana_bin, font=("Courier", 11))
    texto_bin.pack(expand=True, fill="both")

    texto_bin.insert(tk.END, f"Posición\tToken\n")
    texto_bin.insert(tk.END, f"{'-'*32}\n")

    with open(ARCHIVO_BIN, "rb") as f:
        for i in range(NUM_SLOTS):
            f.seek(i * TAM_SLOT)
            datos = f.read(TAM_SLOT)
            if datos.strip(b'\x00'):
                token = datos.decode('utf-8').strip('\x00')
                texto_bin.insert(tk.END, f"{i:03}\t\t{token}\n")

    texto_bin.config(state=tk.DISABLED)

def cargar_desde_archivo():
    archivo = filedialog.askopenfilename(filetypes=[("Archivos de texto", "*.txt")])
    if archivo:
        with open(archivo, "r") as f:
            contenido = f.read()
            editor_text.delete("1.0", tk.END)
            editor_text.insert(tk.END, contenido)

def limpiar_pantalla():
    editor_text.delete("1.0", tk.END)
    resultado_text.config(state=tk.NORMAL)
    resultado_text.delete("1.0", tk.END)
    resultado_text.config(state=tk.DISABLED)
    errores_text.config(state=tk.NORMAL)
    errores_text.delete("1.0", tk.END)
    errores_text.config(state=tk.DISABLED)
    
# --------------------- INTERFAZ ---------------------
root = tk.Tk()
boton_frame = tk.Frame(root)
boton_frame.pack(pady=10)
root.title("Interfaz de Compilador con Tiempos")
root.geometry("900x800")

editor_text = scrolledtext.ScrolledText(root, height=10, width=100, font=("Courier", 12))
editor_text.pack(pady=10)
editor_text.bind("<KeyRelease>", resaltar_palabras)

btn_compilar = tk.Button(boton_frame, text="Analizar / Compilar", command=compilar)
btn_tema = tk.Button(boton_frame, text="Modo Noche", command=alternar_tema)
btn_limpiar_tabla = tk.Button(boton_frame, text="Limpiar Tabla de Símbolos", command=limpiar_tabla)
btn_hash = tk.Button(boton_frame, text="Ver Tabla Hash", command=mostrar_tabla_hash)
btn_tabla_bin = tk.Button(boton_frame, text="Ver Tabla Binaria", command=mostrar_tabla_binaria)
btn_cargar = tk.Button(boton_frame, text="Cargar desde archivo", command=cargar_desde_archivo)
btn_limpiar_pantalla = tk.Button(boton_frame, text="Limpiar Pantalla", command=limpiar_pantalla)

# Primera fila
btn_compilar.grid(row=0, column=0, padx=5, pady=5)
btn_tema.grid(row=0, column=1, padx=5, pady=5)
btn_limpiar_tabla.grid(row=0, column=2, padx=5, pady=5)

# Segunda fila
btn_hash.grid(row=1, column=0, padx=5, pady=5)
btn_tabla_bin.grid(row=1, column=1, padx=5, pady=5)
btn_cargar.grid(row=1, column=2, padx=5, pady=5)

resultado_text = scrolledtext.ScrolledText(root, height=10, width=100, font=("Courier", 12), state=tk.DISABLED)
resultado_text.pack(pady=10)

errores_text = scrolledtext.ScrolledText(root, height=7, width=100, font=("Courier", 12), fg="red", state=tk.DISABLED)
errores_text.pack(pady=10)

inicializar_archivo_binario()
root.mainloop()