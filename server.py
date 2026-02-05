import os
import sys
import threading
import webbrowser
from waitress import serve
from app import create_app

def abrir_navegador(url):
    """Abre el navegador automáticamente después de 1 segundo"""
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()

def run_server(host='127.0.0.1', port=8080, threads=4):
    """
    Inicia el servidor Waitress con la aplicación Flask
    
    Args:
        host (str): Dirección IP del servidor (default: 127.0.0.1)
        port (int): Puerto del servidor (default: 8080)
        threads (int): Número de threads del pool (default: 4)
    """
    app = create_app()
    url = f'http://{host}:{port}/'
    
    print(f"\n{'='*60}")
    print(f"Iniciando servidor Waitress")
    print(f"Dirección: {url}")
    print(f"Threads: {threads}")
    print(f"Entorno: {os.getenv('FLASK_ENV', 'production')}")
    print(f"{'='*60}\n")
    
    # Abrir navegador automáticamente
    abrir_navegador(url)
    
    try:
        serve(
            app,
            host=host,
            port=port,
            threads=threads,
            _quiet=False
        )
    except KeyboardInterrupt:
        print("Servidor detenido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"Error al iniciar el servidor: {e}")
        sys.exit(1)

if __name__ == '__main__':
    # Configuración desde variables de entorno o valores por defecto
    host = os.getenv('SERVER_HOST', '127.0.0.1')
    port = int(os.getenv('SERVER_PORT', 8080))
    threads = int(os.getenv('SERVER_THREADS', 4))
    
    run_server(host=host, port=port, threads=threads)
