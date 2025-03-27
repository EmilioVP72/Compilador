import tkinter as tk
from tkinter import scrolledtext

root = tk.Tk()
root.title("Interfaz de Compilador")
root.geometry("600x400")

# Función para alternar entre modo claro y modo noche
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

editor_text = scrolledtext.ScrolledText(root, height=10, width=70, font=("Courier", 12))
editor_text.pack(pady=10)

btn_compilar = tk.Button(root, text="Compilar")
btn_compilar.pack()

btn_tema = tk.Button(root, text="Modo Noche", command=alternar_tema)
btn_tema.pack()

resultado_text = scrolledtext.ScrolledText(root, height=10, width=70, font=("Courier", 12), state=tk.DISABLED)
resultado_text.pack(pady=10)

tk.mainloop()