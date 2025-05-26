import tkinter as tk
from tkinter import scrolledtext
import re
import os
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

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

    while i < longitud:
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
