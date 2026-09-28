#!/usr/bin/env python3
"""
kali-mcp — servidor MCP para operar una VM Kali desde Claude.

Expone herramientas para ejecutar comandos, manejar archivos y correr
tareas en segundo plano. Pensado para uso sobre TU propia VM.

Transporte: HTTP (streamable-http). Por defecto escucha en 127.0.0.1:8765/mcp

Controles de seguridad:
  - Autenticación obligatoria con Bearer token (KALI_MCP_TOKEN).
  - Escucha solo en localhost salvo que se configure otra interfaz.
  - Allowlist opcional de binarios para run_command/start_task.
  - Herramientas de archivos confinadas a WORKDIR (configurable).
  - Log de auditoría en JSON Lines de cada request y cada herramienta.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from mcp.server.fastmcp import FastMCP


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# --- Configuración (se puede sobreescribir con variables de entorno) ---------
HOST = os.environ.get("KALI_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("KALI_MCP_PORT", "8765"))
# Token Bearer requerido en cada request (Authorization: Bearer <token>).
TOKEN = os.environ.get("KALI_MCP_TOKEN", "")
# Directorio de trabajo por defecto para comandos y rutas relativas.
WORKDIR = Path(os.environ.get("KALI_MCP_WORKDIR", os.path.expanduser("~"))).resolve()
# Timeout por defecto (segundos) para run_command.
DEFAULT_TIMEOUT = int(os.environ.get("KALI_MCP_TIMEOUT", "120"))
# Límite de salida devuelta (caracteres) para no saturar el contexto.
MAX_OUTPUT_CHARS = int(os.environ.get("KALI_MCP_MAX_OUTPUT", "20000"))
# Allowlist de binarios separados por coma (p. ej. "nmap,whois,dig"). Vacío = sin restricción.
ALLOWED_COMMANDS = {c.strip() for c in os.environ.get("KALI_MCP_ALLOWED_COMMANDS", "").split(",") if c.strip()}
# Si está activo, read_file/write_file/list_dir no pueden salir de WORKDIR.
RESTRICT_PATHS = _env_bool("KALI_MCP_RESTRICT_PATHS", True)
# Directorio de estado (logs de tareas y auditoría), con permisos 0700.
STATE_DIR = Path(os.environ.get("KALI_MCP_STATE_DIR", os.path.expanduser("~/.kali-mcp"))).resolve()
AUDIT_LOG = Path(os.environ.get("KALI_MCP_AUDIT_LOG", str(STATE_DIR / "audit.log")))

# Hosts permitidos en el header Host (protección DNS rebinding) al escuchar fuera de localhost,
# p. ej. "192.168.1.50:*". En localhost la protección se activa sola.
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("KALI_MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]

STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

_security = None
if ALLOWED_HOSTS:
    from mcp.server.transport_security import TransportSecuritySettings

    _security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=ALLOWED_HOSTS,
        allowed_origins=[f"http://{h}" for h in ALLOWED_HOSTS],
    )

mcp = FastMCP("kali-mcp", host=HOST, port=PORT, transport_security=_security)


# ============================ Auditoría ======================================
_audit_lock = threading.Lock()


def audit(event: str, **fields) -> None:
    """Agrega una línea JSON al log de auditoría."""
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **fields}
    with _audit_lock:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ============================ Políticas ======================================
# Separadores de comandos encadenados; cada segmento se valida contra la allowlist.
_SEGMENT_SPLIT = re.compile(r"\|\||&&|[|;&\n]")
# Construcciones que permiten ejecutar comandos anidados y evadir la allowlist.
_FORBIDDEN_WITH_ALLOWLIST = ("`", "$(", "<(", ">(")


def check_command(command: str) -> str | None:
    """Devuelve un mensaje de error si el comando viola la allowlist, o None si está permitido."""
    if not ALLOWED_COMMANDS:
        return None
    for token in _FORBIDDEN_WITH_ALLOWLIST:
        if token in command:
            return f"sustitución de comandos ({token}) no permitida con allowlist activa"
    for segment in _SEGMENT_SPLIT.split(command):
        segment = segment.strip()
        if not segment:
            continue
        try:
            words = shlex.split(segment)
        except ValueError as e:
            return f"comando mal formado: {e}"
        # Saltea asignaciones de entorno iniciales (VAR=valor cmd ...)
        words = [w for w in words if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w)] or [""]
        binary = os.path.basename(words[0])
        if binary not in ALLOWED_COMMANDS:
            return f"'{binary}' no está en KALI_MCP_ALLOWED_COMMANDS"
    return None


def _truncate(text: str) -> str:
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    keep = MAX_OUTPUT_CHARS // 2
    omitted = len(text) - 2 * keep
    return f"{text[:keep]}\n\n... [{omitted} caracteres omitidos] ...\n\n{text[-keep:]}"


def _resolve(path: str | None) -> Path:
    """Resuelve una ruta relativa contra WORKDIR; deja las absolutas tal cual."""
    if not path:
        return WORKDIR
    p = Path(path)
    return p if p.is_absolute() else (WORKDIR / p)


def _resolve_confined(path: str | None) -> Path:
    """Como _resolve, pero rechaza rutas fuera de WORKDIR si RESTRICT_PATHS está activo."""
    p = _resolve(path).resolve()
    if RESTRICT_PATHS and p != WORKDIR and WORKDIR not in p.parents:
        raise PermissionError(f"ruta fuera de WORKDIR ({WORKDIR}): {p}")
    return p


# ============================ Comandos =======================================
@mcp.tool()
def run_command(command: str, cwd: str | None = None, timeout: int | None = None) -> str:
    """Ejecuta un comando de shell en la VM y devuelve su salida.

    Args:
        command: Línea de comando a ejecutar (se corre con /bin/bash -c).
        cwd: Directorio de trabajo. Relativo se resuelve contra el WORKDIR.
        timeout: Segundos máximos antes de abortar (por defecto DEFAULT_TIMEOUT).

    Devuelve exit code, stdout y stderr. Para procesos largos usa start_task.
    """
    denied = check_command(command)
    audit("tool", tool="run_command", command=command, cwd=cwd, allowed=denied is None)
    if denied:
        return f"[denegado] {denied}"
    workdir = _resolve(cwd)
    to = timeout or DEFAULT_TIMEOUT
    try:
        proc = subprocess.run(
            command,
            shell=True,
            executable="/bin/bash",
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=to,
        )
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"")
        err = (e.stderr or b"")
        out = out.decode(errors="replace") if isinstance(out, bytes) else out
        err = err.decode(errors="replace") if isinstance(err, bytes) else err
        return (
            f"[TIMEOUT tras {to}s]\n"
            f"--- stdout ---\n{_truncate(out)}\n"
            f"--- stderr ---\n{_truncate(err)}"
        )
    parts = [f"exit_code: {proc.returncode}", f"cwd: {workdir}"]
    if proc.stdout:
        parts.append(f"--- stdout ---\n{_truncate(proc.stdout)}")
    if proc.stderr:
        parts.append(f"--- stderr ---\n{_truncate(proc.stderr)}")
    return "\n".join(parts)


# ============================ Archivos =======================================
@mcp.tool()
def read_file(path: str, max_bytes: int = 200_000) -> str:
    """Lee un archivo de texto de la VM. Ruta relativa se resuelve contra WORKDIR."""
    audit("tool", tool="read_file", path=path)
    try:
        p = _resolve_confined(path)
    except PermissionError as e:
        return f"[denegado] {e}"
    if not p.exists():
        return f"[error] no existe: {p}"
    if not p.is_file():
        return f"[error] no es un archivo: {p}"
    data = p.read_bytes()[:max_bytes]
    return _truncate(data.decode(errors="replace"))


@mcp.tool()
def write_file(path: str, content: str, append: bool = False) -> str:
    """Escribe (o agrega) contenido de texto en un archivo. Crea carpetas padre."""
    audit("tool", tool="write_file", path=path, append=append, chars=len(content))
    try:
        p = _resolve_confined(path)
    except PermissionError as e:
        return f"[denegado] {e}"
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with open(p, mode, encoding="utf-8") as f:
        f.write(content)
    return f"[ok] {'agregado a' if append else 'escrito'} {p} ({len(content)} caracteres)"


@mcp.tool()
def list_dir(path: str | None = None) -> str:
    """Lista el contenido de un directorio (por defecto WORKDIR)."""
    try:
        p = _resolve_confined(path)
    except PermissionError as e:
        return f"[denegado] {e}"
    if not p.is_dir():
        return f"[error] no es un directorio: {p}"
    rows = []
    for entry in sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
        try:
            size = entry.stat().st_size
        except OSError:
            size = 0
        kind = "d" if entry.is_dir() else "f"
        rows.append(f"{kind}  {size:>10}  {entry.name}")
    header = f"{p}  ({len(rows)} entradas)"
    return header + "\n" + "\n".join(rows) if rows else header + "\n(vacío)"


# ==================== Tareas en segundo plano ================================
@dataclass
class Task:
    id: str
    command: str
    cwd: str
    proc: subprocess.Popen
    stdout_path: Path
    started_at: float = field(default_factory=time.time)


_tasks: dict[str, Task] = {}
_tasks_lock = threading.Lock()
_LOG_DIR = Path(os.environ.get("KALI_MCP_LOGDIR", str(STATE_DIR / "tasks")))
_LOG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)


@mcp.tool()
def start_task(command: str, cwd: str | None = None) -> str:
    """Lanza un comando en segundo plano y devuelve un task_id.

    Útil para procesos largos. Consulta el avance con task_status(task_id)
    y detén con stop_task(task_id). La salida (stdout+stderr) se guarda en un log.
    """
    denied = check_command(command)
    audit("tool", tool="start_task", command=command, cwd=cwd, allowed=denied is None)
    if denied:
        return f"[denegado] {denied}"
    workdir = _resolve(cwd)
    task_id = uuid.uuid4().hex[:8]
    log_path = _LOG_DIR / f"{task_id}.log"
    log_file = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        command,
        shell=True,
        executable="/bin/bash",
        cwd=str(workdir),
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,  # grupo propio -> permite matar hijos
    )
    with _tasks_lock:
        _tasks[task_id] = Task(task_id, command, str(workdir), proc, log_path)
    return f"[ok] task iniciada: {task_id}\ncomando: {command}\nlog: {log_path}"


@mcp.tool()
def task_status(task_id: str, tail_lines: int = 100) -> str:
    """Devuelve el estado de una tarea y las últimas líneas de su salida."""
    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return f"[error] task_id desconocido: {task_id}"
    rc = task.proc.poll()
    state = "corriendo" if rc is None else f"terminada (exit_code={rc})"
    elapsed = int(time.time() - task.started_at)
    try:
        lines = task.stdout_path.read_text(errors="replace").splitlines()
        tail = "\n".join(lines[-tail_lines:])
    except OSError:
        tail = "(sin salida aún)"
    return (
        f"task: {task.id}\nestado: {state}\ntranscurrido: {elapsed}s\n"
        f"comando: {task.command}\n--- últimas {tail_lines} líneas ---\n{_truncate(tail)}"
    )


@mcp.tool()
def list_tasks() -> str:
    """Lista todas las tareas conocidas y su estado."""
    with _tasks_lock:
        tasks = list(_tasks.values())
    if not tasks:
        return "(no hay tareas)"
    rows = []
    for t in tasks:
        rc = t.proc.poll()
        state = "corriendo" if rc is None else f"exit={rc}"
        rows.append(f"{t.id}  {state:>12}  {t.command}")
    return "\n".join(rows)


@mcp.tool()
def stop_task(task_id: str) -> str:
    """Detiene una tarea en segundo plano (SIGTERM al grupo, luego SIGKILL)."""
    audit("tool", tool="stop_task", task_id=task_id)
    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task:
        return f"[error] task_id desconocido: {task_id}"
    if task.proc.poll() is not None:
        return f"[ok] la task {task_id} ya había terminado"
    try:
        os.killpg(os.getpgid(task.proc.pid), signal.SIGTERM)
        try:
            task.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(task.proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    return f"[ok] task {task_id} detenida"


# ============================ Info del sistema ===============================
@mcp.tool()
def system_info() -> str:
    """Devuelve información básica del entorno de la VM."""
    cmds = {
        "hostname": "hostname",
        "kernel": "uname -a",
        "distro": "cat /etc/os-release 2>/dev/null | head -n 2",
        "uptime": "uptime",
        "disk": "df -h / 2>/dev/null",
        "mem": "free -h 2>/dev/null",
        "ip": "hostname -I 2>/dev/null",
    }
    out = [f"WORKDIR: {WORKDIR}"]
    for name, cmd in cmds.items():
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            out.append(f"[{name}] {r.stdout.strip()}")
        except Exception as e:  # noqa: BLE001
            out.append(f"[{name}] error: {e}")
    return "\n".join(out)


# ============================ Autenticación ==================================
class BearerAuthMiddleware:
    """Middleware ASGI que exige Authorization: Bearer <token> en cada request HTTP."""

    def __init__(self, app, token: str):
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        provided = headers.get(b"authorization", b"")
        client = (scope.get("client") or ("?", 0))[0]
        if not hmac.compare_digest(provided, self.expected):
            audit("auth_failed", client=client, path=scope.get("path"))
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")],
            })
            await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
            return
        audit("request", client=client, method=scope.get("method"), path=scope.get("path"))
        return await self.app(scope, receive, send)


def build_app():
    return BearerAuthMiddleware(mcp.streamable_http_app(), TOKEN)


if __name__ == "__main__":
    import uvicorn

    if len(TOKEN) < 32:
        print(
            "[error] Definí KALI_MCP_TOKEN con al menos 32 caracteres antes de arrancar.\n"
            f"        Ejemplo: export KALI_MCP_TOKEN={secrets.token_urlsafe(32)}",
            file=sys.stderr,
        )
        sys.exit(1)
    if HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"[aviso] escuchando en {HOST}: limitá el acceso con un firewall (ver README).", file=sys.stderr)
    allow = ", ".join(sorted(ALLOWED_COMMANDS)) or "sin restricción"
    print(f"kali-mcp escuchando en http://{HOST}:{PORT}/mcp  (WORKDIR={WORKDIR}, allowlist: {allow})")
    audit("startup", host=HOST, port=PORT, allowlist=sorted(ALLOWED_COMMANDS), restrict_paths=RESTRICT_PATHS)
    uvicorn.run(build_app(), host=HOST, port=PORT, log_level="info")
