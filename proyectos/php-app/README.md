# Módulo PHP Backend — Sistema de Registro de Contacto (Lab 09.2)

**Asignatura:** Desarrollo de Aplicaciones Web (IS093A) — UNCP FIS  
**Estudiante / Dev PHP & QA:** Arlette D'Alessandra Suárez Román (2022200427L)  
**Arquitecto de Despliegue & Colaborador:** José Pablo Osorio Mallqui (2022200839H)  
**Docente:** Ing. Miguel Aguilar  

---

## 1. Descripción del Módulo
Este módulo implementa el procesamiento del lado del servidor bajo el motor PHP 8.x. Recibe datos de contacto mediante peticiones HTTP estrictamente enviadas por el método `POST`, aplica validaciones de formato, neutraliza vulnerabilidades de Cross-Site Scripting (XSS) y almacena los registros en memoria mediante `$_SESSION`.

## 2. Características Técnicas y de Seguridad
- **Restricción de Método HTTP:** Si la solicitud no proviene de `POST`, el backend rechaza la ejecución y emite un código de respuesta `405 Method Not Allowed`.
- **Sanitización XSS:** Se implementa `htmlspecialchars()` con flags `ENT_QUOTES` y codificación `UTF-8` para convertir caracteres de control `< > " ' &` en entidades HTML inocuas.
- **Validación de Correo:** Implementación de `filter_input()` con el validador nativo `FILTER_VALIDATE_EMAIL` (RFC 5322).
- **Gestión de Estado:** Manejo de sesiones persistentes con `session_start()`, aislando los contactos del usuario por `PHPSESSID`.
- **Telemetría en Vivo:** Medición de tiempo de ejecución de script (`microtime`), versión de PHP, ID de sesión y uso de memoria en bytes.

## 3. Instrucciones de Ejecución

### Opción A: Servidor embebido de PHP (Recomendado para pruebas rápidas)
Ejecutar el archivo `run.bat` o desde la terminal:
```bash
php -S localhost:8000 -t .
```
Luego abrir en el navegador: [http://localhost:8000/index.html](http://localhost:8000/index.html).

### Opción B: Apache / Laragon / XAMPP
Copiar o enlazar la carpeta `php-app` dentro de `C:/laragon/www/` o `C:/xampp/htdocs/` y acceder a través de:
[http://localhost/php-app/index.html](http://localhost/php-app/index.html).

## 4. Estructura de Archivos
```
php-app/
├── index.html        # Formulario de entrada con validación HTML5
├── procesar.php      # Controlador backend, validación, XSS sanitization y render de tabla
├── run.bat           # Script de arranque en un clic
└── README.md         # Documentación técnica del módulo
```
