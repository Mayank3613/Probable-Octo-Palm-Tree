import subprocess
import sys
import os
import time
import socket
import threading
import urllib.request

# Color definitions
COLORS = {
    "BACKEND": "\033[94m",      # Blue
    "DASHBOARD": "\033[92m",    # Green
    "AGENT": "\033[93m",        # Yellow
    "AI_ENGINE": "\033[96m",    # Cyan
    "SYSTEM": "\033[95m",       # Magenta
    "RESET": "\033[0m"
}

# Process tracker
processes = []

def resolve_service_python(base_dir, service_dir):
    """Returns the service-specific venv Python path when available, otherwise falls back to sys.executable."""
    if sys.platform == "win32":
        venv_python = os.path.join(base_dir, service_dir, ".venv", "Scripts", "python.exe")
    else:
        venv_python = os.path.join(base_dir, service_dir, ".venv", "bin", "python")

    if os.path.exists(venv_python):
        print_colored("SYSTEM", "SYSTEM", f"Using virtualenv Python for {service_dir}: {venv_python}\n")
        return venv_python

    print_colored("SYSTEM", "SYSTEM", f"No virtualenv found for {service_dir}; falling back to {sys.executable}\n")
    return sys.executable

def print_colored(prefix, color_name, line):
    color = COLORS.get(color_name, COLORS["RESET"])
    print(f"{color}[{prefix}]{COLORS['RESET']} {line}", end="")
    sys.stdout.flush()

def stream_logs(process, prefix, color_name):
    """Reads lines from the subprocess and prints them with a colored prefix."""
    for line in iter(process.stdout.readline, ''):
        if not line:
            break
        print_colored(prefix, color_name, line)

def run_service(name, command, cwd, color_name):
    """Spawns a subprocess and starts a thread to stream its logs."""
    print_colored("SYSTEM", "SYSTEM", f"Starting {name}...\n")
    
    # Use shell=True on Windows for npm commands
    use_shell = sys.platform == "win32" and "npm" in command[0]
    
    # Resolve npm to npm.cmd on Windows
    if sys.platform == "win32" and command[0] == "npm":
        command[0] = "npm.cmd"

    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        shell=use_shell
    )
    processes.append(process)
    
    thread = threading.Thread(target=stream_logs, args=(process, name, color_name))
    thread.daemon = True
    thread.start()
    return process

def wait_for_port(port, name, timeout=60):
    """Polls the local port until it opens."""
    start_time = time.time()
    print_colored("SYSTEM", "SYSTEM", f"Waiting for {name} on port {port}...\n")
    while time.time() - start_time < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', int(port)))
            if result == 0:
                print_colored("SYSTEM", "SYSTEM", f"{name} is UP on port {port}!\n")
                return True
        time.sleep(1)
    print_colored("SYSTEM", "SYSTEM", f"TIMEOUT waiting for {name} on port {port}!\n")
    return False

def run_health_checks():
    """Validates the system is running correctly."""
    print_colored("SYSTEM", "SYSTEM", "Running Health Checks...\n")
    try:
        # Check Backend
        req = urllib.request.urlopen("http://127.0.0.1:8000/health")
        if req.getcode() == 200:
            print_colored("SYSTEM", "SYSTEM", "[PASS] Backend API Health Check: OK\n")
        
        # Check AI Engine
        req = urllib.request.urlopen("http://127.0.0.1:8001/health")
        if req.getcode() == 200:
            print_colored("SYSTEM", "SYSTEM", "[PASS] AI Engine Health Check: OK\n")
        
        # Check Dashboard
        req = urllib.request.urlopen("http://127.0.0.1:3000")
        if req.getcode() == 200:
            print_colored("SYSTEM", "SYSTEM", "[PASS] Dashboard Health Check: OK\n")
            
        print_colored("SYSTEM", "SYSTEM", "\n[READY] ALL SYSTEMS NOMINAL AND RUNNING! Press Ctrl+C to stop.\n")
    except Exception as e:
        print_colored("SYSTEM", "SYSTEM", f"[FAIL] Health Check Failed: {str(e)}\n")

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    backend_python = resolve_service_python(base_dir, "backend-api")
    agent_python = resolve_service_python(base_dir, "local-agent")
    ai_python = resolve_service_python(base_dir, "ai-engine")
    
    try:
        # 1. Start Backend API
        run_service(
            name="BACKEND",
            command=[backend_python, "-m", "uvicorn", "app.main:app", "--reload"],
            cwd=os.path.join(base_dir, "backend-api"),
            color_name="BACKEND"
        )
        
        # 2. Start Vite Dashboard
        run_service(
            name="DASHBOARD",
            command=["npm", "run", "dev"],
            cwd=os.path.join(base_dir, "dashboard"),
            color_name="DASHBOARD"
        )
        
        # 3. Start Local Agent
        run_service(
            name="AGENT",
            command=[agent_python, "agent_main.py"],
            cwd=os.path.join(base_dir, "local-agent"),
            color_name="AGENT"
        )
        
        # 4. Start AI Engine
        run_service(
            name="AI_ENGINE",
            command=[ai_python, "-m", "uvicorn", "app:app", "--port", "8001"],
            cwd=os.path.join(base_dir, "ai-engine"),
            color_name="AI_ENGINE"
        )
        
        # Wait for servers to boot
        if wait_for_port(8000, "Backend API") and wait_for_port(8001, "AI Engine") and wait_for_port(3000, "Dashboard"):
            run_health_checks()
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print_colored("SYSTEM", "SYSTEM", "\nShutting down all services...\n")
    finally:
        for p in processes:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                p.kill()
        print_colored("SYSTEM", "SYSTEM", "Goodbye!\n")

if __name__ == "__main__":
    # Fix console colors for Windows
    if sys.platform == "win32":
        os.system('color')
    main()
