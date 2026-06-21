# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec do PhishGuard.

Build:
    pip install pyinstaller
    pyinstaller PhishGuard.spec --noconfirm

Saída:
    dist/PhishGuard.exe  (executável único, já com manifest de Administrador)

Observação: o Npcap NÃO é embutido — o usuário precisa tê-lo instalado
(https://npcap.com/). Os arquivos de dados (blacklist/whitelist/populares)
são embutidos e, na primeira execução, extraídos para uma pasta "data" ao
lado do .exe, ficando editáveis pelo programa.
"""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ICON = "gui/escudo-de-seguranca.ico"

# Dados da aplicação + assets do CustomTkinter (temas/ícones) + ícone da janela.
datas = [("data", "data"), (ICON, "gui")]
datas += collect_data_files("customtkinter")

# Scapy faz muitos imports dinâmicos de camadas — coleta os submódulos.
hiddenimports = collect_submodules("scapy")

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="PhishGuard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,        # Aplicação GUI — sem janela de console.
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,       # Solicita elevação (Administrador) ao abrir.
    icon=ICON,
)
