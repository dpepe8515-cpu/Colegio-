# Plataforma Colegio Dr. Agustín Cueva Tamariz (etapa 1)
Flask + SQLite (persistente en ./data). Requiere Python 3.10+ y `pip install flask`.

## Ejecutar
    export PROD=1 BASE_URL=https://tu-dominio SMTP_HOST=... SMTP_PORT=587 SMTP_USER=... SMTP_PASS=... SMTP_FROM=...
    flask --app app create-admin     # crea el administrador principal (pide correo y contraseña)
    python app.py                    # puerto 8000; poner detrás de HTTPS (nginx/Caddy)
    python test_app.py               # pruebas

## Respaldo
Copiar la carpeta `data/` (app.db, media, receipts, secret.key) con la app detenida o con `sqlite3 data/app.db ".backup respaldo.db"`.

## Pendiente (no implementado)
- Pagos con tarjeta: requiere cuenta comercial y credenciales de la pasarela elegida; no hay código de cobro.
- Portal de representantes con login, recibos descargables, reembolsos, exportación de informes, MFA, WhatsApp oficial, avisos de vencimiento, política de retención.
- Correos: se encolan en la tabla `outbox`; solo se envían si se configura SMTP.
