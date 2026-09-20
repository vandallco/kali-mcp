# kali-mcp

Servidor MCP para operar tu VM Kali desde Claude (Claude Code / Claude Desktop).
Claude actúa como el agente; este servidor le da las herramientas para ejecutar
comandos, manejar archivos y correr tareas en segundo plano dentro de la VM.

## Herramientas expuestas

| Tool | Qué hace |
|------|----------|
| `run_command` | Ejecuta un comando de shell con timeout y captura stdout/stderr |
| `read_file` / `write_file` | Lee / escribe archivos de texto |
| `list_dir` | Lista un directorio |
| `start_task` / `task_status` / `list_tasks` / `stop_task` | Procesos largos en background |
| `system_info` | Info básica de la VM (kernel, IP, disco, RAM) |

## 1. Instalar en Kali

```bash
# En la VM Kali
sudo mkdir -p /opt/kali-mcp && sudo chown "$USER" /opt/kali-mcp
# Copia server.py y requirements.txt a /opt/kali-mcp (scp, carpeta compartida, git, etc.)

cd /opt/kali-mcp
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 2. Probar a mano

```bash
cd /opt/kali-mcp
KALI_MCP_WORKDIR=/home/kali .venv/bin/python server.py
# -> kali-mcp escuchando en http://0.0.0.0:8765/mcp
```

Comprueba la IP de la VM con `hostname -I`. Necesitas red **puente (bridge)** o
un **port-forward** en el hipervisor para llegar desde Windows:

- **VirtualBox:** red NAT + reenvío de puerto host `8765` → guest `8765`, o adaptador puente.
- **VMware:** adaptador puente (bridged) y usa la IP de la VM directamente.

## 3. Dejarlo como servicio (arranca solo)

```bash
sudo cp /opt/kali-mcp/kali-mcp.service /etc/systemd/system/
# Edita User= y las rutas si tu usuario no es "kali"
sudo systemctl daemon-reload
sudo systemctl enable --now kali-mcp
systemctl status kali-mcp
```

## 4. Agregarlo a Claude en Windows

En Claude Code (terminal `claude` interactiva):

```bash
claude mcp add --transport http kali http://IP_DE_TU_KALI:8765/mcp
```

Reemplaza `IP_DE_TU_KALI` (p. ej. `192.168.1.50`, o `127.0.0.1` si usas
port-forward al host). Verifica con `/mcp` dentro de Claude Code.

Para **Claude Desktop**, en `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "kali": {
      "url": "http://IP_DE_TU_KALI:8765/mcp",
      "transport": "http"
    }
  }
}
```

## Configuración (variables de entorno)

| Variable | Default | Descripción |
|----------|---------|-------------|
| `KALI_MCP_HOST` | `0.0.0.0` | Interfaz de escucha |
| `KALI_MCP_PORT` | `8765` | Puerto |
| `KALI_MCP_WORKDIR` | `~` | Directorio base para rutas relativas y comandos |
| `KALI_MCP_TIMEOUT` | `120` | Timeout por defecto de `run_command` (s) |
| `KALI_MCP_MAX_OUTPUT` | `20000` | Límite de caracteres devueltos |

## Seguridad

- El servidor **ejecuta comandos arbitrarios** en la VM. Mantenlo en una red de
  confianza (host-only / red local), nunca expuesto a internet.
- `0.0.0.0` escucha en todas las interfaces. Si solo lo usas vía port-forward,
  puedes poner `KALI_MCP_HOST=127.0.0.1` para no exponerlo en la LAN.
- Considera un firewall (`ufw allow from <IP_de_tu_Windows> to any port 8765`).
- Es para operar **tu propia** VM; trátalo como acceso shell remoto.
