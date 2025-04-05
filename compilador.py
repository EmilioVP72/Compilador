import tkinter as tk
from tkinter import scrolledtext
import re
import os
#Mensaje para checar si vale 3 hectarias de verga mi conexión funka o no

# Palabras reservadas 
PALABRAS_RESERVADAS = [
    "class", "init", "end", "if", "else", "while", "for", "switch", "case", "default",
    "puts", "full", "half", "bin", "crs", "chain"
]

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

# Función para tokenizar y mostrar el resultado
def compilar():
    texto = editor_text.get("1.0", tk.END)
    tokens = re.findall(r"[a-zA-Z_]\w*|\d+\.\d+|\d+|==|!=|<=|>=|[+\-*/=<>:{}()\[\];,.]", texto)
    resultado_text.config(state=tk.NORMAL)
    resultado_text.delete("1.0", tk.END)
    resultado_text.insert(tk.END, "Tokens encontrados:\n\n")
    for token in tokens:
        resultado_text.insert(tk.END, f"{token}\n")
    resultado_text.config(state=tk.DISABLED)

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

root = tk.Tk()
root.title("Interfaz de Compilador")
root.geometry("700x500")

editor_text = scrolledtext.ScrolledText(root, height=10, width=80, font=("Courier", 12))
editor_text.pack(pady=10)
editor_text.bind("<KeyRelease>", resaltar_palabras)

btn_compilar = tk.Button(root, text="Compilar", command=compilar)
btn_compilar.pack()

btn_tema = tk.Button(root, text="Modo Noche", command=alternar_tema)
btn_tema.pack()

resultado_text = scrolledtext.ScrolledText(root, height=10, width=80, font=("Courier", 12), state=tk.DISABLED)
resultado_text.pack(pady=10)

root.mainloop()
