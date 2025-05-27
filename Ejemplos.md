# Ejemplos de Estructuras de Control

# IF
if (x > 10) {  
    puts("x es mayor que 10");  
}

if (x == 5) {  
    puts("x es igual a 5");  
} else {  
    puts("x no es igual a 5");  
}

if (x > 10) {  
    puts("x es mayor que 10");  
} elsif (x == 10) {  
    puts("x es igual a 10");  
} else {  
    puts("x es menor que 10");  
}

# While
while (x < 10) {  
    puts("x es menor que 10");  
    x = x + 1;  
}

# FOR
for (x < 10) {  
    puts("x es menor que 10");  
    x = x + 1;  
}

# Until 
until (x > 10) {
    puts("x es menor que 10");
}

# Switch
switch (opcion) {  
    case 1:  
        puts("Seleccionaste la opción 1");  
        break;  
    case 2:  
        puts("Seleccionaste la opción 2");  
        break;  
    default:  
        puts("Opción no válida");  
}

# Lista - List

# Matriz (Opcional)
matriz = [ [1, 2], [3, 4] ];  
puts(matriz[1][0]);  // Imprime 3  



