import tkinter as tk
from tkinter import scrolledtext
import re
import os

# Palabras reservadas
PALABRAS_RESERVADAS = [
    "class", "init", "end", "if", "else", "while", "for", "switch", "case", "default",
    "puts", "full", "half", "bin", "crs", "chain"
]

# --------------------- MANEJO DE LA TABLA DE SÍMBOLOS ---------------------
TABLA_SIMBOLOS = "Tabla_de_simbolos.txt"
if not os.path.exists(TABLA_SIMBOLOS):
    with open(TABLA_SIMBOLOS, "w") as archivo:
        for palabra in PALABRAS_RESERVADAS:
            archivo.write(f"{palabra}\n")

def resaltar_palabras(event=None):
    editor_text.tag_remove("reservada", "1.0", tk.END)
    texto = editor_text.get("1.0", tk.END)
    for palabra in PALABRAS_RESERVADAS:
        for match in re.finditer(rf'\b{palabra}\b', texto):
            inicio = f"1.0 + {match.start()} chars"
            final = f"1.0 + {match.end()} chars"
            editor_text.tag_add("reservada", inicio, final)
    editor_text.tag_config("reservada", foreground="green")

def limpiar_tabla():
    with open(TABLA_SIMBOLOS, "w") as archivo:
        for palabra in PALABRAS_RESERVADAS:
            archivo.write(f"{palabra}\n")

# --------------------- FUNCIONES PARA LOS AFD ---------------------
def es_identificador(token):
    # AFD para identificar identificadores válidos
    estado = 0
    for char in token:
        if estado == 0:
            if char.isalpha() or char == "_":
                estado = 1
            else:
                return False
        elif estado == 1:
            if char.isalnum() or char == "_":
                estado = 1
            else:
                return False
    return estado == 1

def es_numero(token):
    estado = 0
    for char in token:
        if estado == 0:
            if char.isdigit():
                estado = 1
            else:
                return False
        elif estado == 1:
            if char.isdigit():
                continue
            elif char == ".":
                estado = 2
            else:
                return False
        elif estado == 2:
            if char.isdigit():
                estado = 3
            else:
                return False
        elif estado == 3:
            if char.isdigit():
                continue
            else:
                return False
    return estado == 1 or estado == 3  # Acepta enteros (1) o decimales (3)

# --------------------- INTERFAZ Y COMPILACIÓN ---------------------
def agregar_a_tabla_simbolos(token):
    with open(TABLA_SIMBOLOS, "r+") as archivo:
        contenido = archivo.read().splitlines()
        if token not in contenido:
            archivo.write(f"{token}\n")

# Función para tokenizar y mostrar el resultado
def compilar():
    texto = editor_text.get("1.0", tk.END)
    tokens = re.findall(r"[a-zA-Z_]\w*|\d+\.\d+|\d+|==|!=|<=|>=|[+\-*/=<>:{}()\[\];,.]", texto)

    # Limpia áreas
    resultado_text.config(state=tk.NORMAL)
    resultado_text.delete("1.0", tk.END)
    errores_text.config(state=tk.NORMAL)
    errores_text.delete("1.0", tk.END)

    resultado_text.insert(tk.END, "Tokens encontrados:\n\n")
    errores_text.insert(tk.END, "Errores encontrados:\n\n")

    for token in tokens:
        resultado_text.insert(tk.END, f"{token}\n")
        if es_identificador(token) and token not in PALABRAS_RESERVADAS:
            agregar_a_tabla_simbolos(token)
        elif es_numero(token):
            agregar_a_tabla_simbolos(token)
        elif token not in PALABRAS_RESERVADAS:
            errores_text.insert(tk.END, f"Token no reconocido: {token}\n")

    resultado_text.config(state=tk.DISABLED)
    errores_text.config(state=tk.DISABLED)



def alternar_tema():
    if root.option_get("theme", "light") == "light":
        root.tk_setPalette(background="#2E2E2E", foreground="white")
        editor_text.config(bg="#1E1E1E", fg="white", insertbackground="white")
        resultado_text.config(bg="#1E1E1E", fg="white")
        btn_compilar.config(bg="#444", fg="white")
        btn_tema.config(bg="#444", fg="white")
        root.option_add("*theme", "dark")
    else:
        root.tk_setPalette(background="white", foreground="black")
        editor_text.config(bg="white", fg="black", insertbackground="black")
        resultado_text.config(bg="white", fg="black")
        btn_compilar.config(bg="lightgray", fg="black")
        btn_tema.config(bg="lightgray", fg="black")
        root.option_add("*theme", "light")


# --------------------- INTERFAZ GRÁFICA ---------------------
root = tk.Tk()
root.title("Interfaz de Compilador")
root.geometry("700x500")

editor_text = scrolledtext.ScrolledText(root, height=10, width=80, font=("Courier", 12))
editor_text.pack(pady=10)
editor_text.bind("<KeyRelease>", resaltar_palabras)

btn_compilar = tk.Button(root, text="Analizar / Compilar", command=compilar)
btn_compilar.pack()

btn_tema = tk.Button(root, text="Modo Noche", command=alternar_tema)
btn_tema.pack()

btn_limpiar = tk.Button(root, text="Limpiar Tabla de Símbolos", command=limpiar_tabla)
btn_limpiar.pack()

resultado_text = scrolledtext.ScrolledText(root, height=10, width=80, font=("Courier", 12), state=tk.DISABLED)
resultado_text.pack(pady=10)

#Errores
errores_text = scrolledtext.ScrolledText(root, height=7, width=80, font=("Courier", 12), fg="red", state=tk.DISABLED)
errores_text.pack(pady=10)


root.mainloop()