<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" import="java.util.*, java.time.*, java.time.format.DateTimeFormatter, jakarta.servlet.http.*" %>
<%!
    // Método de sanitización estricta contra ataques Cross-Site Scripting (XSS)
    public String sanitizar(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;")
                    .trim();
    }
%>
<%
    long startNano = System.nanoTime();

    // 1. RESTRICCIÓN DE MÉTODO HTTP (Seguridad - 405 Method Not Allowed)
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        response.setHeader("Allow", "POST");
%>
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <title>405 Method Not Allowed</title>
            <style>
                body { font-family: -apple-system, sans-serif; background: #fff1f2; color: #9f1239; padding: 3rem; text-align: center; }
                .card { background: white; max-width: 500px; margin: 0 auto; padding: 2rem; border-radius: 12px; border: 1px solid #fecdd3; }
                h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
                a { color: #e11d48; text-decoration: none; font-weight: 600; }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>Error 405: Método No Permitido (Tomcat JSP)</h1>
                <p>Solo se admiten envíos mediante el método <strong>POST</strong>.</p>
                <p style="margin-top: 1rem;"><a href="index.jsp">&larr; Volver al formulario JSP</a></p>
            </div>
        </body>
        </html>
<%
        return;
    }

    HttpSession miSesion = request.getSession(true);

    // Opción para limpiar la sesión
    String accion = request.getParameter("accion");
    if ("limpiar".equals(accion)) {
        synchronized(miSesion) {
            miSesion.removeAttribute("registros");
        }
        response.sendRedirect("procesar.jsp");
        return;
    }

    // 2. CAPTURA Y VALIDACIÓN DE PARÁMETROS
    String nombreRaw = request.getParameter("nombre");
    String correoRaw = request.getParameter("correo");

    List<String> errores = new ArrayList<>();

    if (nombreRaw == null || nombreRaw.trim().length() < 3) {
        errores.add("El campo 'Nombre Completo' es obligatorio y debe tener al menos 3 caracteres.");
    }

    String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
    if (correoRaw == null || !correoRaw.trim().matches(emailRegex)) {
        errores.add("El 'Correo Electrónico' ingresado no presenta una estructura válida.");
    }

    String nombreSanitizado = sanitizar(nombreRaw);
    String correoSanitizado = sanitizar(correoRaw);

    // 3. PERSISTENCIA EN HttpSession (Sincronizada para concurrencia de hilos)
    if (errores.isEmpty()) {
        synchronized(miSesion) {
            @SuppressWarnings("unchecked")
            List<Map<String, String>> lista = (List<Map<String, String>>) miSesion.getAttribute("registros");
            if (lista == null) {
                lista = new ArrayList<>();
            }
            Map<String, String> reg = new LinkedHashMap<>();
            reg.put("id", String.valueOf(lista.size() + 1));
            reg.put("nombre", nombreSanitizado);
            reg.put("correo", correoSanitizado);
            reg.put("fecha", LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")));
            reg.put("thread", Thread.currentThread().getName());
            reg.put("ip", request.getRemoteAddr());
            lista.add(reg);
            miSesion.setAttribute("registros", lista);
        }
        response.setStatus(HttpServletResponse.SC_OK);
    } else {
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    }

    @SuppressWarnings("unchecked")
    List<Map<String, String>> registros = (List<Map<String, String>>) miSesion.getAttribute("registros");
    if (registros == null) {
        registros = Collections.emptyList();
    }

    double tiempoEjecucionMs = (System.nanoTime() - startNano) / 1_000_000.0;
    Runtime rt = Runtime.getRuntime();
    long memoriaUsadaMb = (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
    long memoriaTotalMb = rt.totalMemory() / (1024 * 1024);
%>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lab 09.2 | Tabla de Registros (JSP / Tomcat)</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #c2410c;
            --primary-dark: #9a3412;
            --accent: #ea580c;
            --bg-body: #f8fafc;
            --surface: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --radius: 14px;
            --shadow: 0 10px 25px -5px rgba(15, 23, 42, 0.08);
            --success: #10b981;
            --danger: #ef4444;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-body);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 2.5rem 1rem;
        }

        .container {
            width: 100%;
            max-width: 840px;
            background: var(--surface);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #18181b 0%, #27272a 100%);
            padding: 2rem 2.5rem;
            color: #ffffff;
            border-bottom: 3px solid var(--primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .header h1 {
            font-size: 1.4rem;
            font-weight: 700;
        }

        .header p {
            color: #a1a1aa;
            font-size: 0.85rem;
            margin-top: 0.25rem;
        }

        .badge-status {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            background: rgba(16, 185, 129, 0.2);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.4);
            font-size: 0.8rem;
            font-weight: 700;
            padding: 0.4rem 0.85rem;
            border-radius: 9999px;
            font-family: monospace;
        }

        .badge-status.error {
            background: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border-color: rgba(239, 68, 68, 0.4);
        }

        .content {
            padding: 2rem 2.5rem;
        }

        .telemetry-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
        }

        .metric {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
        }

        .metric-label {
            font-size: 0.725rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .metric-value {
            font-size: 0.92rem;
            font-weight: 700;
            color: var(--text-main);
            font-family: monospace;
            word-break: break-all;
        }

        .alert-error {
            background: #fef2f2;
            border-left: 4px solid var(--danger);
            padding: 1rem 1.25rem;
            border-radius: 6px;
            margin-bottom: 1.5rem;
            color: #991b1b;
            font-size: 0.9rem;
        }

        .section-title {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .section-title h2 {
            font-size: 1.15rem;
            font-weight: 700;
            color: #1e293b;
        }

        .count-pill {
            background: #ffedd5;
            color: #c2410c;
            font-weight: 700;
            font-size: 0.75rem;
            padding: 0.25rem 0.65rem;
            border-radius: 9999px;
        }

        .table-wrapper {
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            text-align: left;
        }

        thead {
            background-color: #f1f5f9;
            color: #475569;
            font-weight: 600;
            border-bottom: 2px solid var(--border);
        }

        th, td {
            padding: 0.85rem 1.1rem;
        }

        tbody tr {
            border-bottom: 1px solid var(--border);
            transition: background-color 0.15s ease;
        }

        tbody tr:last-child {
            border-bottom: none;
        }

        tbody tr:hover {
            background-color: #f8fafc;
        }

        td.code-cell {
            font-family: monospace;
            color: #c2410c;
            font-weight: 500;
        }

        .actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.65rem 1.25rem;
            font-size: 0.9rem;
            font-weight: 600;
            border-radius: 8px;
            text-decoration: none;
            transition: all 0.2s ease;
            cursor: pointer;
            border: none;
        }

        .btn-primary {
            background-color: var(--primary);
            color: #fff;
        }

        .btn-primary:hover {
            background-color: var(--primary-dark);
        }

        .btn-secondary {
            background-color: #f1f5f9;
            color: #475569;
            border: 1px solid var(--border);
        }

        .btn-secondary:hover {
            background-color: #e2e8f0;
            color: #1e293b;
        }

        .footer {
            margin-top: 1.5rem;
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
        }
    </style>
</head>
<body>

    <div class="container">
        <header class="header">
            <div>
                <h1>Gestión de Contactos Almacenados</h1>
                <p>Módulo JSP 3.1 / Jakarta EE • Servlets en Apache Tomcat 10</p>
            </div>
            <div>
                <% if (errores.isEmpty()) { %>
                    <span class="badge-status">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                            <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                        HTTP 200 OK
                    </span>
                <% } else { %>
                    <span class="badge-status error">HTTP 400 Bad Request</span>
                <% } %>
            </div>
        </header>

        <div class="content">

            <!-- Diagnóstico de Arquitectura / Telemetría JVM -->
            <div class="telemetry-grid">
                <div class="metric">
                    <span class="metric-label">Contenedor Servlets</span>
                    <span class="metric-value"><%= application.getServerInfo().split("/")[0] %></span>
                </div>
                <div class="metric">
                    <span class="metric-label">Hilo Concurrente</span>
                    <span class="metric-value" title="<%= Thread.currentThread().getName() %>">
                        <%= Thread.currentThread().getName().length() > 14 ? Thread.currentThread().getName().substring(0, 14) + "..." : Thread.currentThread().getName() %>
                    </span>
                </div>
                <div class="metric">
                    <span class="metric-label">Heap JVM (Usada/Total)</span>
                    <span class="metric-value"><%= memoriaUsadaMb %>MB / <%= memoriaTotalMb %>MB</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Latencia Backend</span>
                    <span class="metric-value"><%= String.format(Locale.US, "%.2f", tiempoEjecucionMs) %> ms</span>
                </div>
            </div>

            <% if (!errores.isEmpty()) { %>
                <div class="alert-error">
                    <strong>Error en la validación:</strong>
                    <ul style="margin-left: 1.25rem; margin-top: 0.5rem;">
                        <% for (String err : errores) { %>
                            <li><%= err %></li>
                        <% } %>
                    </ul>
                </div>
            <% } %>

            <div class="section-title">
                <h2>Registros en HttpSession</h2>
                <span class="count-pill"><%= registros.size() %> Registrado(s)</span>
            </div>

            <!-- Tabla de Registros Sanitizados -->
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 50px;">#</th>
                            <th>Nombre Completo (Sanitizado)</th>
                            <th>Correo Electrónico</th>
                            <th>Timestamp Servidor</th>
                            <th>Hilo JVM</th>
                        </tr>
                    </thead>
                    <tbody>
                        <% if (registros.isEmpty()) { %>
                            <tr>
                                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                                    No hay contactos registrados aún en la sesión de Tomcat.
                                </td>
                            </tr>
                        <% } else { %>
                            <% for (int i = 0; i < registros.size(); i++) {
                                Map<String, String> reg = registros.get(i);
                            %>
                                <tr>
                                    <td class="code-cell"><%= i + 1 %></td>
                                    <td><strong><%= reg.get("nombre") %></strong></td>
                                    <td class="code-cell"><%= reg.get("correo") %></td>
                                    <td style="color: #64748b; font-size: 0.85rem;"><%= reg.get("fecha") %></td>
                                    <td style="color: #64748b; font-size: 0.82rem; font-family: monospace;"><%= reg.get("thread") %></td>
                                </tr>
                            <% } %>
                        <% } %>
                    </tbody>
                </table>
            </div>

            <div class="actions">
                <a href="index.jsp" class="btn btn-primary">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <line x1="12" y1="5" x2="12" y2="19"></line>
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                    </svg>
                    Nuevo Registro
                </a>

                <form method="POST" action="procesar.jsp" style="margin: 0; display: inline;">
                    <input type="hidden" name="accion" value="limpiar">
                    <button type="submit" class="btn btn-secondary" onclick="return confirm('¿Seguro que deseas reiniciar la sesión en Tomcat?')">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="1 4 1 10 7 10"></polyline>
                            <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"></path>
                        </svg>
                        Reiniciar Sesión
                    </button>
                </form>
            </div>

        </div>
    </div>

    <div class="footer">
        UNCP FIS — Desarrollo de Aplicaciones Web | Autoría: José P. Osorio Mallqui & Arlette D. Suárez Román
    </div>

</body>
</html>
