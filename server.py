#!/usr/bin/env python3
"""
kali-mcp — servidor MCP para operar una VM Kali desde Claude.

Expone herramientas para ejecutar comandos, manejar archivos y correr
tareas en segundo plano. Pensado para uso sobre TU propia VM.

Transporte: HTTP (streamable-http). Por defecto escucha en 0.0.0.0:8765/mcp
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# --- Configuración (se puede sobreescribir con variables de entorno) ---------
HOST = os.environ.get("KALI_MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("KALI_MCP_PORT", "8765"))
# Directorio de trabajo por defecto para comandos y rutas relativas.
WORKDIR = Path(os.environ.get("KALI_MCP_WORKDIR", os.path.expanduser("~"))).resolve()
# Timeout por defecto (segundos) para run_command.
DEFAULT_TIMEOUT = int(os.environ.get("KALI_MCP_TIMEOUT", "120"))
# Límite de salida devuelta (caracteres) para no saturar el contexto.
MAX_OUTPUT_CHARS = int(os.environ.get("KALI_MCP_MAX_OUTPUT", "20000"))

mcp = FastMCP("kali-mcp")


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
    p = _resolve(path)
    if not p.exists():
        return f"[error] no existe: {p}"
    if not p.is_file():
        return f"[error] no es un archivo: {p}"
    data = p.read_bytes()[:max_bytes]
    return _truncate(data.decode(errors="replace"))


@mcp.tool()
def write_file(path: str, content: str, append: bool = False) -> str:
    """Escribe (o agrega) contenido de texto en un archivo. Crea carpetas padre."""
    p = _resolve(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with open(p, mode, encoding="utf-8") as f:
        f.write(content)
    return f"[ok] {'agregado a' if append else 'escrito'} {p} ({len(content)} caracteres)"


@mcp.tool()
def list_dir(path: str | None = None) -> str:
    """Lista el contenido de un directorio (por defecto WORKDIR)."""
    p = _resolve(path)
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
_LOG_DIR = Path(os.environ.get("KALI_MCP_LOGDIR", "/tmp/kali-mcp-tasks"))
_LOG_DIR.mkdir(parents=True, exist_ok=True)


@mcp.tool()
def start_task(command: str, cwd: str | None = None) -> str:
    """Lanza un comando en segundo plano y devuelve un task_id.

    Útil para procesos largos. Consulta el avance con task_status(task_id)
    y detén con stop_task(task_id). La salida (stdout+stderr) se guarda en un log.
    """
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


if __name__ == "__main__":
    mcp.settings.host = HOST
    mcp.settings.port = PORT
    print(f"kali-mcp escuchando en http://{HOST}:{PORT}/mcp  (WORKDIR={WORKDIR})")
    mcp.run(transport="streamable-http")
