<?php
/**
 * Laboratorio 09.2 - Desarrollo de Aplicaciones Web (IS093A) - UNCP FIS
 * Módulo Backend PHP: Procesamiento, Sanitización XSS y Gestión de Sesión
 * Autoría Técnica:
 *   - Desarrolladora PHP & QA: Arlette D'Alessandra Suárez Román (2022200427L)
 *   - Arquitecto de Despliegue: José Pablo Osorio Mallqui (2022200839H)
 */

$start_time = microtime(true);

// 1. RESTRICCIÓN DE MÉTODO HTTP (Seguridad Básica - 405 Method Not Allowed)
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    ?>
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
            <h1>Error 405: Método HTTP No Permitido</h1>
            <p>Este recurso solo acepta solicitudes mediante <strong>POST</strong>.</p>
            <p style="margin-top: 1rem;"><a href="index.html">&larr; Volver al formulario</a></p>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// 2. INICIO DE SESIÓN
session_start();

if (!isset($_SESSION['registros'])) {
    $_SESSION['registros'] = [];
}

// Opción para limpiar la sesión
if (isset($_POST['accion']) && $_POST['accion'] === 'limpiar') {
    $_SESSION['registros'] = [];
    header('Location: procesar.php');
    exit;
}

// 3. CAPTURA Y SANITIZACIÓN RIGUROSA (Prevención XSS y validación de tipos)
$raw_nombre = filter_input(INPUT_POST, 'nombre', FILTER_DEFAULT);
$raw_correo = filter_input(INPUT_POST, 'correo', FILTER_DEFAULT);

// Sanitización contra inyección Cross-Site Scripting (XSS)
$nombre_sanitizado = htmlspecialchars(trim((string)$raw_nombre), ENT_QUOTES, 'UTF-8');

// Validación de formato de correo electrónico RFC 5322
$correo_validado = filter_var(trim((string)$raw_correo), FILTER_VALIDATE_EMAIL);

// Verificación de campos obligatorios
$errores = [];
if (empty($nombre_sanitizado) || mb_strlen($nombre_sanitizado) < 3) {
    $errores[] = "El campo 'Nombre' es obligatorio y debe tener al menos 3 caracteres.";
}
if (!$correo_validado) {
    $errores[] = "El 'Correo Electrónico' proporcionado no tiene un formato válido.";
}

// Si hay errores, responder 400 Bad Request
if (!empty($errores)) {
    http_response_code(400);
} else {
    // 4. ALMACENAMIENTO EN ESTADO DE SESIÓN ($_SESSION)
    $nuevo_registro = [
        'id'        => count($_SESSION['registros']) + 1,
        'nombre'    => $nombre_sanitizado,
        'correo'    => htmlspecialchars($correo_validado, ENT_QUOTES, 'UTF-8'),
        'timestamp' => date('d/m/Y H:i:s'),
        'ip'        => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1'
    ];
    $_SESSION['registros'][] = $nuevo_registro;
    http_response_code(200);
}

$execution_time = round((microtime(true) - $start_time) * 1000, 2);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lab 09.2 | Tabla de Registros (PHP)</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #0284c7;
            --primary-dark: #0369a1;
            --accent: #38bdf8;
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
            max-width: 820px;
            background: var(--surface);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--border);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
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
            color: #94a3b8;
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
            font-size: 0.95rem;
            font-weight: 700;
            color: var(--text-main);
            font-family: monospace;
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
            background: #e0f2fe;
            color: #0369a1;
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
            color: #0369a1;
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
                <p>Módulo PHP 8.x • Almacenamiento en Memoria de Sesión</p>
            </div>
            <div>
                <?php if (empty($errores)): ?>
                    <span class="badge-status">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                            <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                        HTTP 200 OK
                    </span>
                <?php else: ?>
                    <span class="badge-status error">HTTP 400 Bad Request</span>
                <?php endif; ?>
            </div>
        </header>

        <div class="content">

            <!-- Diagnóstico de Arquitectura / Telemetría -->
            <div class="telemetry-grid">
                <div class="metric">
                    <span class="metric-label">Motor Backend</span>
                    <span class="metric-value">PHP <?= PHP_VERSION ?></span>
                </div>
                <div class="metric">
                    <span class="metric-label">ID de Sesión</span>
                    <span class="metric-value" title="<?= session_id() ?>"><?= substr(session_id(), 0, 10) ?>...</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Tiempo Render</span>
                    <span class="metric-value"><?= $execution_time ?> ms</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Uso de Memoria</span>
                    <span class="metric-value"><?= round(memory_get_usage() / 1024, 1) ?> KB</span>
                </div>
            </div>

            <?php if (!empty($errores)): ?>
                <div class="alert-error">
                    <strong>Error en la validación:</strong>
                    <ul style="margin-left: 1.25rem; margin-top: 0.5rem;">
                        <?php foreach ($errores as $err): ?>
                            <li><?= $err ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <div class="section-title">
                <h2>Registros en $_SESSION</h2>
                <span class="count-pill"><?= count($_SESSION['registros']) ?> Registrado(s)</span>
            </div>

            <!-- Tabla de Registros Sanitizados -->
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 50px;">#</th>
                            <th>Nombre Completo (Sanitizado)</th>
                            <th>Correo Electrónico</th>
                            <th>Fecha y Hora</th>
                            <th>IP Cliente</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($_SESSION['registros'])): ?>
                            <tr>
                                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                                    No hay contactos registrados aún en la sesión actual.
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($_SESSION['registros'] as $idx => $reg): ?>
                                <tr>
                                    <td class="code-cell"><?= htmlspecialchars((string)($idx + 1)) ?></td>
                                    <td><strong><?= $reg['nombre'] ?></strong></td>
                                    <td class="code-cell"><?= $reg['correo'] ?></td>
                                    <td style="color: #64748b; font-size: 0.85rem;"><?= $reg['timestamp'] ?? '-' ?></td>
                                    <td style="color: #64748b; font-size: 0.85rem;"><?= $reg['ip'] ?? '-' ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <div class="actions">
                <a href="index.html" class="btn btn-primary">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                        <line x1="12" y1="5" x2="12" y2="19"></line>
                        <line x1="5" y1="12" x2="19" y2="12"></line>
                    </svg>
                    Nuevo Registro
                </a>

                <form method="POST" action="procesar.php" style="margin: 0; display: inline;">
                    <input type="hidden" name="accion" value="limpiar">
                    <button type="submit" class="btn btn-secondary" onclick="return confirm('¿Seguro que deseas reiniciar la sesión?')">
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
        UNCP FIS — Desarrollo de Aplicaciones Web | Autoría: Arlette D. Suárez Román & José P. Osorio Mallqui
    </div>

</body>
</html>
