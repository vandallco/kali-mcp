# kali-mcp

[![tests](https://github.com/vandallco/kali-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/vandallco/kali-mcp/actions/workflows/tests.yml)

Servidor MCP para operar tu VM Kali desde Claude (Claude Code / Claude Desktop).
Claude actúa como el agente; este servidor le da las herramientas para ejecutar
comandos, manejar archivos y correr tareas en segundo plano dentro de la VM.

Como expone ejecución remota de comandos, está diseñado con **controles de seguridad
por defecto**: autenticación obligatoria, escucha local, allowlist de comandos,
confinamiento de rutas y log de auditoría.

## Herramientas expuestas

| Tool | Qué hace |
|------|----------|
| `run_command` | Ejecuta un comando de shell con timeout y captura stdout/stderr |
| `read_file` / `write_file` | Lee / escribe archivos de texto (confinados a `WORKDIR`) |
| `list_dir` | Lista un directorio (confinado a `WORKDIR`) |
| `start_task` / `task_status` / `list_tasks` / `stop_task` | Procesos largos en background |
| `system_info` | Info básica de la VM (kernel, IP, disco, RAM) |

## Modelo de amenazas y controles

| Riesgo | Control |
|--------|---------|
| Cualquier equipo de la red ejecuta comandos en la VM | **Bearer token obligatorio** (`KALI_MCP_TOKEN`, mínimo 32 caracteres). El servidor no arranca sin él. Comparación en tiempo constante (`hmac.compare_digest`). |
| Exposición accidental en la LAN | Escucha en **`127.0.0.1` por defecto**. Exponerlo requiere configurarlo explícitamente. |
| DNS rebinding desde un navegador | Validación del header `Host` en localhost (automática) o con `KALI_MCP_ALLOWED_HOSTS` en la LAN. |
| El agente ejecuta algo destructivo o fuera de alcance | **Allowlist opcional** de binarios (`KALI_MCP_ALLOWED_COMMANDS`). Valida cada segmento de pipes y encadenamientos (`\|`, `;`, `&&`) y bloquea la sustitución de comandos (`$( )`, backticks). |
| Lectura o escritura de archivos sensibles (`/etc/shadow`, llaves SSH) | Herramientas de archivos **confinadas a `WORKDIR`**, con bloqueo de path traversal (`../`). |
| Falta de trazabilidad | **Log de auditoría** en JSON Lines: arranque, requests, fallos de autenticación y cada invocación de herramienta con sus argumentos. |
| Logs de tareas legibles por otros usuarios | Estado en `~/.kali-mcp` con permisos `0700` (antes `/tmp`). |

> La allowlist es defensa en profundidad, no un sandbox: un binario permitido que a su vez
> ejecuta comandos (p. ej. `find -exec`) puede evadirla. Para aislamiento real, corré el
> servidor con un usuario sin privilegios dentro de la VM.

## 1. Instalar en Kali

```bash
# En la VM Kali
sudo mkdir -p /opt/kali-mcp && sudo chown "$USER" /opt/kali-mcp
git clone https://github.com/vandallco/kali-mcp.git /opt/kali-mcp

cd /opt/kali-mcp
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 2. Generar el token y probar a mano

```bash
export KALI_MCP_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo "$KALI_MCP_TOKEN"   # guardalo: lo vas a usar en Claude

cd /opt/kali-mcp
KALI_MCP_WORKDIR=/home/kali .venv/bin/python server.py
# -> kali-mcp escuchando en http://127.0.0.1:8765/mcp
```

Para llegar desde Windows tenés dos opciones:

- **Recomendada: port-forward** (el servidor sigue en `127.0.0.1`).
  - VirtualBox: red NAT con reenvío de puerto host `127.0.0.1:8765` → guest `8765`.
  - Cualquier hipervisor: túnel SSH desde Windows, `ssh -L 8765:127.0.0.1:8765 kali@IP_DE_TU_KALI`.
- **Red puente (bridged):** `KALI_MCP_HOST=0.0.0.0`, `KALI_MCP_ALLOWED_HOSTS=IP_DE_TU_KALI:*`
  y un firewall que solo acepte a tu PC:

  ```bash
  sudo ufw default deny incoming
  sudo ufw allow from IP_DE_TU_WINDOWS to any port 8765 proto tcp
  sudo ufw enable
  ```

## 3. Dejarlo como servicio (arranca solo)

```bash
sudo cp /opt/kali-mcp/kali-mcp.env.example /etc/kali-mcp.env
sudo nano /etc/kali-mcp.env          # poné tu token y ajustá rutas
sudo chmod 600 /etc/kali-mcp.env
sudo cp /opt/kali-mcp/kali-mcp.service /etc/systemd/system/
# Edita User= y las rutas si tu usuario no es "kali"
sudo systemctl daemon-reload
sudo systemctl enable --now kali-mcp
systemctl status kali-mcp
```

## 4. Agregarlo a Claude en Windows

En Claude Code (terminal `claude` interactiva):

```bash
claude mcp add --transport http kali http://127.0.0.1:8765/mcp --header "Authorization: Bearer TU_TOKEN"
```

Usá `127.0.0.1` con port-forward o la IP de la VM en modo puente. Verificá con `/mcp` dentro de Claude Code.

Para **Claude Desktop**, en `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kali": {
      "url": "http://127.0.0.1:8765/mcp",
      "transport": "http",
      "headers": { "Authorization": "Bearer TU_TOKEN" }
    }
  }
}
```

## Configuración (variables de entorno)

| Variable | Default | Descripción |
|----------|---------|-------------|
| `KALI_MCP_TOKEN` | *(obligatorio)* | Bearer token, mínimo 32 caracteres |
| `KALI_MCP_HOST` | `127.0.0.1` | Interfaz de escucha |
| `KALI_MCP_PORT` | `8765` | Puerto |
| `KALI_MCP_ALLOWED_HOSTS` | *(vacío)* | Hosts permitidos en el header `Host` al escuchar en la LAN (p. ej. `192.168.1.50:*`) |
| `KALI_MCP_WORKDIR` | `~` | Directorio base para comandos y límite de las herramientas de archivos |
| `KALI_MCP_RESTRICT_PATHS` | `true` | Confina `read_file`/`write_file`/`list_dir` a `WORKDIR` |
| `KALI_MCP_ALLOWED_COMMANDS` | *(vacío = sin restricción)* | Binarios permitidos, separados por coma (p. ej. `nmap,whois,dig`) |
| `KALI_MCP_STATE_DIR` | `~/.kali-mcp` | Logs de tareas y auditoría (permisos `0700`) |
| `KALI_MCP_AUDIT_LOG` | `$STATE_DIR/audit.log` | Ruta del log de auditoría |
| `KALI_MCP_TIMEOUT` | `120` | Timeout por defecto de `run_command` (s) |
| `KALI_MCP_MAX_OUTPUT` | `20000` | Límite de caracteres devueltos |

## Log de auditoría

Cada evento es una línea JSON, fácil de ingerir en un SIEM (Splunk, Wazuh, ELK):

```json
{"ts": "2026-09-28T01:02:41-0300", "event": "startup", "host": "127.0.0.1", "port": 8765, "allowlist": [], "restrict_paths": true}
{"ts": "2026-09-28T01:02:44-0300", "event": "auth_failed", "client": "127.0.0.1", "path": "/mcp"}
{"ts": "2026-09-28T01:03:10-0300", "event": "tool", "tool": "run_command", "command": "nmap -sV 10.0.0.5", "cwd": null, "allowed": true}
```

## Tests

```bash
pip install -r requirements.txt httpx
python -m unittest discover -s tests -v
```

Cubren la allowlist (pipes, encadenamientos, sustitución de comandos), el confinamiento de rutas
(path traversal, rutas absolutas) y la autenticación (sin token, token inválido, token válido y
auditoría de fallos). Corren en cada push con GitHub Actions.

## Uso responsable

Es para operar **tu propia** VM o sistemas sobre los que tenés autorización. Tratalo como un acceso
shell remoto: nunca lo expongas a internet.
