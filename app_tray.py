import os
import sys
import time
import multiprocessing
import webbrowser
from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as item

def get_base_path():
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return sys._MEIPASS
    return os.path.abspath(".")

# ============================================================
# MICROSERVICE ENTRYPOINTS
# ============================================================

def run_backend():
    base_path = get_base_path()
    backend_path = os.path.join(base_path, "backend-api")
    os.chdir(backend_path)
    sys.path.insert(0, backend_path)
    import uvicorn
    from app.main import app
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

def run_ai_engine():
    base_path = get_base_path()
    ai_engine_path = os.path.join(base_path, "ai-engine")
    os.chdir(ai_engine_path)
    sys.path.insert(0, ai_engine_path)
    import uvicorn
    from app import app
    uvicorn.run(app, host="127.0.0.1", port=8001, log_level="warning")

def run_agent():
    base_path = get_base_path()
    agent_path = os.path.join(base_path, "local-agent")
    os.chdir(agent_path)
    sys.path.insert(0, agent_path)
    import threading
    from agent_main import monitor_network, start_packet_capture, start_ransomware_monitor
    
    threading.Thread(target=monitor_network, daemon=True).start()
    threading.Thread(target=start_packet_capture, daemon=True).start()
    threading.Thread(target=start_ransomware_monitor, daemon=True).start()
    
    while True:
        time.sleep(1)

# ============================================================
# SYSTEM TRAY
# ============================================================

# Global process list
processes = []

def create_image():
    # Simple Octo-Palm Tree icon
    image = Image.new('RGB', (64, 64), color=(10, 15, 25))
    dc = ImageDraw.Draw(image)
    # Tree trunk
    dc.rectangle((28, 32, 36, 60), fill=(139, 69, 19))
    # Leaves
    dc.ellipse((16, 16, 48, 48), fill=(46, 204, 113))
    return image

def open_dashboard(icon, item):
    webbrowser.open("http://127.0.0.1:8000")

def quit_app(icon, item):
    icon.stop()
    for p in processes:
        if p.is_alive():
            p.terminate()
            p.join(timeout=2)
    sys.exit(0)

def main():
    multiprocessing.freeze_support()
    
    print("[SYSTEM] Starting OctoPlamTree Application...")
    
    p1 = multiprocessing.Process(target=run_backend, daemon=True)
    p2 = multiprocessing.Process(target=run_ai_engine, daemon=True)
    p3 = multiprocessing.Process(target=run_agent, daemon=True)
    
    processes.extend([p1, p2, p3])
    
    for p in processes:
        p.start()
        
    print("[SYSTEM] All services started. Check System Tray.")
    
    icon = pystray.Icon(
        "OctoPlamTree",
        create_image(),
        "OctoPlamTree Security",
        menu=pystray.Menu(
            item('Open Dashboard', open_dashboard),
            item('Quit', quit_app)
        )
    )
    icon.run()

if __name__ == "__main__":
    main()
