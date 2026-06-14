"""
PhishGuard — Monitor de Rede Doméstica
=======================================

Protótipo para identificação de phishing em redes domésticas
por meio da análise de requisições DNS.

Uso:
    Executar como Administrador (necessário para captura de pacotes):
    > python main.py

Requisitos:
    - Python 3.10+
    - Npcap instalado (https://npcap.com/)
    - pip install -r requirements.txt
"""

import sys
import logging
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent))

from config import config, LOGS_DIR

def setup_logging():
    """Configure application logging."""
    LOGS_DIR.mkdir(exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.FileHandler(config.log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )

def check_admin():
    if sys.platform != "win32":
        return True

    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True

    # MB_YESNO (0x04) | MB_ICONQUESTION (0x20)
    result = ctypes.windll.user32.MessageBoxW(
        0,
        "O PhishGuard precisa de permissões de Administrador para "
        "capturar pacotes de rede corretamente.\n\n"
        "🔒 Recomendação: Executar como Administrador é necessário "
        "para garantir o melhor funcionamento do monitoramento DNS "
        "e a interceptação de tráfego pela placa de rede.\n\n"
        "Deseja reiniciar como Administrador?",
        "PhishGuard — Permissões de Administrador",
        0x24,
    )

    IDYES = 6
    if result == IDYES:
        import os
        script = os.path.abspath(sys.argv[0])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}"', None, 1,
        )
        sys.exit(0)

    # User chose No — continue without admin
    logging.warning(
        "⚠️  Continuando sem privilégios de Administrador. "
        "A captura de pacotes pode falhar."
    )
    return False


def check_dependencies():
    missing = []
    try:
        import scapy
    except ImportError:
        missing.append("scapy")

    try:
        import customtkinter
    except ImportError:
        missing.append("customtkinter")

    if missing:
        print(f"❌ Dependências faltando: {', '.join(missing)}")
        print(f"   Instale com: pip install -r requirements.txt")
        sys.exit(1)


def main():
    setup_logging()
    logger = logging.getLogger("phishguard")

    logger.info("=" * 50)
    logger.info("PhishGuard — Monitor de Rede Doméstica")
    logger.info("TCC UNISINOS 2025 — Rodrigo Dalavia Fechner")
    logger.info("=" * 50)

    check_dependencies()
    check_admin()

    logger.info("Iniciando interface gráfica...")

    from gui.app import PhishGuardApp

    app = PhishGuardApp()
    app.mainloop()

    logger.info("PhishGuard encerrado.")


if __name__ == "__main__":
    main()
