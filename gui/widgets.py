"""
PhishGuard — Custom Widgets

Reusable UI components for the PhishGuard dashboard.
Built with CustomTkinter for a modern dark-theme look.
"""

import customtkinter as ctk


class StatCard(ctk.CTkFrame):
    """
    A statistics card showing a label and a large number.
    Used for the top stats bar (Total, Safe, Suspicious, Malicious).
    """

    def __init__(self, master, title: str, value: str = "0",
                 accent_color: str = "#3498db", **kwargs):
        super().__init__(master, corner_radius=12, **kwargs)

        self._accent = accent_color

        # Configure grid
        self.grid_columnconfigure(0, weight=1)

        # Title label
        self.title_label = ctk.CTkLabel(
            self, text=title,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#a0a0a0",
        )
        self.title_label.grid(row=0, column=0, padx=15, pady=(12, 0), sticky="w")

        # Value label (large number)
        self.value_label = ctk.CTkLabel(
            self, text=value,
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=accent_color,
        )
        self.value_label.grid(row=1, column=0, padx=15, pady=(0, 12), sticky="w")

        # Accent bar at top
        self.accent_bar = ctk.CTkFrame(
            self, height=3, corner_radius=0,
            fg_color=accent_color,
        )
        self.accent_bar.grid(row=0, column=0, sticky="new", padx=1, pady=1)

    def update_value(self, value: str | int):
        """Update the displayed number."""
        self.value_label.configure(text=str(value))


class EventDetailPanel(ctk.CTkFrame):
    """
    Panel showing detailed information about a selected DNS event.
    Displays domain, classification, reasons, and recommendations.
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, corner_radius=12, **kwargs)
        self.grid_columnconfigure(0, weight=1)

        # Header
        self.header = ctk.CTkLabel(
            self, text="📋 Detalhes do Evento",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        self.header.grid(row=0, column=0, padx=15, pady=(12, 5), sticky="w")

        # Separator
        self.sep = ctk.CTkFrame(self, height=1, fg_color="#404040")
        self.sep.grid(row=1, column=0, padx=15, sticky="ew")

        # Domain
        self.domain_label = ctk.CTkLabel(
            self, text="Selecione um evento para ver detalhes",
            font=ctk.CTkFont(size=12),
            text_color="#888888",
            anchor="w",
            wraplength=400,
        )
        self.domain_label.grid(row=2, column=0, padx=15, pady=(10, 2), sticky="w")

        # Status badge
        self.status_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
        )
        self.status_label.grid(row=3, column=0, padx=15, pady=2, sticky="w")

        # Score
        self.score_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=11),
            text_color="#a0a0a0",
            anchor="w",
        )
        self.score_label.grid(row=4, column=0, padx=15, pady=2, sticky="w")

        # Capture Info
        self.capture_info_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=11),
            text_color="#888888",
            anchor="w",
        )
        self.capture_info_label.grid(row=5, column=0, padx=15, pady=2, sticky="w")

        # Domain Description
        self.description_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=11, slant="italic"),
            text_color="#3498db",
            anchor="w",
            wraplength=400,
        )
        self.description_label.grid(row=6, column=0, padx=15, pady=(2, 10), sticky="w")

        # Reasons
        self.reasons_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=11),
            text_color="#cccccc",
            anchor="w",
            justify="left",
            wraplength=400,
        )
        self.reasons_label.grid(row=7, column=0, padx=15, pady=2, sticky="w")

        # Recommendation
        self.recommendation_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=11),
            text_color="#f0c040",
            anchor="w",
            justify="left",
            wraplength=400,
        )
        self.recommendation_label.grid(row=8, column=0, padx=15, pady=(5, 15), sticky="w")

    def show_event(self, domain: str, status: str, status_color: str,
                   score: int, reasons: list[str], recommendation: str,
                   protocol: str = "UDP", query_type: str = "A", src_ip: str = "N/A", description: str = ""):
        """Update the panel with event details."""
        self.domain_label.configure(
            text=f"🌐 Domínio: {domain}",
            text_color="#ffffff",
        )
        self.status_label.configure(
            text=f"Status: {status}",
            text_color=status_color,
        )
        self.score_label.configure(
            text=f"Pontuação de risco: {score}/100",
        )
        
        self.capture_info_label.configure(
            text=f"📡 Captura: Origem: {src_ip} | Protocolo: {protocol} | Tipo: {query_type}"
        )
        
        self.description_label.configure(
            text=f"ℹ️ Sobre o domínio: {description}" if description else ""
        )

        if reasons:
            reasons_text = "Motivos:\n" + "\n".join(f"  • {r}" for r in reasons)
        else:
            reasons_text = "Nenhum indicador de risco encontrado."
        self.reasons_label.configure(text=reasons_text)

        self.recommendation_label.configure(text=f"💡 {recommendation}")

    def clear(self):
        """Reset the panel to empty state."""
        self.domain_label.configure(
            text="Selecione um evento para ver detalhes",
            text_color="#888888",
        )
        self.status_label.configure(text="")
        self.score_label.configure(text="")
        self.capture_info_label.configure(text="")
        self.description_label.configure(text="")
        self.reasons_label.configure(text="")
        self.recommendation_label.configure(text="")


class StatusBar(ctk.CTkFrame):
    """Bottom status bar showing capture state and info."""

    def __init__(self, master, **kwargs):
        super().__init__(master, height=30, corner_radius=0, **kwargs)
        self.grid_columnconfigure(1, weight=1)

        self.status_indicator = ctk.CTkLabel(
            self, text="⏹ Parado",
            font=ctk.CTkFont(size=11),
            text_color="#e74c3c",
        )
        self.status_indicator.grid(row=0, column=0, padx=10, pady=3)

        self.info_label = ctk.CTkLabel(
            self, text="PhishGuard MVP — TCC UNISINOS 2025",
            font=ctk.CTkFont(size=10),
            text_color="#666666",
        )
        self.info_label.grid(row=0, column=1, padx=10, pady=3)

        self.blacklist_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=10),
            text_color="#666666",
        )
        self.blacklist_label.grid(row=0, column=2, padx=10, pady=3)

    def set_running(self, packet_count: int = 0):
        self.status_indicator.configure(
            text=f"🔴 Capturando... ({packet_count} pacotes)",
            text_color="#2ecc71",
        )

    def set_stopped(self):
        self.status_indicator.configure(
            text="⏹ Parado",
            text_color="#e74c3c",
        )

    def set_blacklist_info(self, count: int):
        self.blacklist_label.configure(
            text=f"📋 Blacklist: {count} domínios",
        )


class InterfaceSelectorFrame(ctk.CTkFrame):
    """
    Initial screen that lists all available network interfaces
    and lets the user pick one before starting packet capture.
    """

    _ICON_MAP = {
        "wi-fi": "📶", "wireless": "📶", "wlan": "📶",
        "ethernet": "🔌", "eth": "🔌",
        "bluetooth": "🔵",
    }

    def __init__(self, master, on_select: callable, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._on_select = on_select

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Main wrapper to keep everything centered
        main_wrapper = ctk.CTkFrame(self, fg_color="transparent")
        main_wrapper.grid(row=0, column=0, sticky="nsew")
        main_wrapper.grid_columnconfigure(0, weight=1)
        main_wrapper.grid_rowconfigure(2, weight=1) # Allow cards area to expand

        # Header
        header = ctk.CTkFrame(main_wrapper, fg_color="transparent")
        header.grid(row=0, column=0, pady=(50, 5))

        ctk.CTkLabel(
            header, text="🛡️  PhishGuard",
            font=ctk.CTkFont(size=36, weight="bold"),
        ).pack()

        ctk.CTkLabel(
            header, text="Monitor de Rede Doméstica",
            font=ctk.CTkFont(size=16), text_color="#888888",
        ).pack(pady=(0, 5))

        # Instruction
        ctk.CTkLabel(
            main_wrapper,
            text="Selecione a interface de rede para monitorar:",
            font=ctk.CTkFont(size=14), text_color="#a0a0a0",
        ).grid(row=1, column=0, pady=(10, 10))

        # Scrollable Cards container
        cards_scroll = ctk.CTkScrollableFrame(main_wrapper, fg_color="transparent")
        cards_scroll.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 10))
        # 4-column grid: spacer | card | card | spacer → centers the pair
        cards_scroll.grid_columnconfigure(0, weight=1)
        cards_scroll.grid_columnconfigure(1, weight=0)
        cards_scroll.grid_columnconfigure(2, weight=0)
        cards_scroll.grid_columnconfigure(3, weight=1)

        interfaces = self._detect_interfaces()

        if not interfaces:
            ctk.CTkLabel(
                cards_scroll,
                text="❌ Nenhuma interface encontrada.\n"
                     "Verifique se o Npcap está instalado e execute como Administrador.",
                font=ctk.CTkFont(size=14), text_color="#e74c3c",
            ).grid(row=0, column=1, columnspan=2, pady=30)
            return

        for i, iface in enumerate(interfaces):
            card = self._create_card(cards_scroll, iface)
            card.grid(row=i // 2, column=(i % 2) + 1, padx=10, pady=10)

        # Footer
        ctk.CTkLabel(
            main_wrapper,
            text="⚠️  Execute como Administrador para captura de pacotes",
            font=ctk.CTkFont(size=11), text_color="#666666",
        ).grid(row=3, column=0, pady=(10, 30))


    # ------------------------------------------------------------------

    # Keywords that indicate irrelevant virtual/system adapters
    _SKIP_KEYWORDS = (
        "wan miniport", "bluetooth", "teredo", "isatap", "6to4",
        "wi-fi direct", "kernel debug", "microsoft hosted",
        "pseudo-interface", "npcap",
    )

    def _is_relevant_interface(self, name: str, desc: str, ip: str) -> bool:
        """Keep only interfaces that matter: physical adapters or VMs with real IPs."""
        combined = (name + " " + desc).lower()

        if "loopback" in combined:
            return False

        for skip in self._SKIP_KEYWORDS:
            if skip in combined:
                return False

        is_physical = any(kw in combined for kw in ("ethernet", "wi-fi", "wireless", "wlan"))
        has_ip = ip and ip != "Sem IP"

        return is_physical or has_ip

    def _detect_interfaces(self) -> list[dict]:
        """Return a list of dicts with interface info from Scapy."""
        interfaces = []
        try:
            from scapy.all import conf
            for iface in conf.ifaces.values():
                name = getattr(iface, "name", str(iface))
                desc = getattr(iface, "description", "")
                ip = getattr(iface, "ip", "") or "Sem IP"
                mac = getattr(iface, "mac", "") or "N/A"

                if not self._is_relevant_interface(name, desc, ip):
                    continue

                icon = "🌐"
                for key, emoji in self._ICON_MAP.items():
                    if key in (name + " " + desc).lower():
                        icon = emoji
                        break

                interfaces.append({
                    "name": name, "description": desc,
                    "ip": ip, "mac": mac, "icon": icon,
                })
        except Exception as e:
            import logging
            logging.getLogger(__name__).error("Interface detection failed: %s", e)
        return interfaces

    def _create_card(self, parent, iface: dict) -> ctk.CTkFrame:
        """Build a clickable card for one network interface."""
        card = ctk.CTkFrame(
            parent, corner_radius=12, width=380, height=110,
            border_width=2, border_color="#333333",
        )
        card.grid_propagate(False)
        card.grid_columnconfigure(1, weight=1)

        icon = ctk.CTkLabel(card, text=iface["icon"], font=ctk.CTkFont(size=34))
        icon.grid(row=0, column=0, rowspan=3, padx=(15, 10), pady=10)

        name = ctk.CTkLabel(
            card, text=iface["name"],
            font=ctk.CTkFont(size=15, weight="bold"), anchor="w",
        )
        name.grid(row=0, column=1, padx=(0, 15), pady=(12, 0), sticky="w")

        desc = ctk.CTkLabel(
            card, text=iface["description"],
            font=ctk.CTkFont(size=11), text_color="#888888", anchor="w",
        )
        desc.grid(row=1, column=1, padx=(0, 15), sticky="w")

        info = ctk.CTkLabel(
            card, text=f"IP: {iface['ip']}  |  MAC: {iface['mac']}",
            font=ctk.CTkFont(size=10), text_color="#666666", anchor="w",
        )
        info.grid(row=2, column=1, padx=(0, 15), pady=(0, 12), sticky="w")

        # Click + hover bindings
        iface_name = iface["name"]
        widgets = [card, icon, name, desc, info]
        for w in widgets:
            w.bind("<Button-1>", lambda _e, n=iface_name: self._on_select(n))
            w.configure(cursor="hand2")
            w.bind("<Enter>", lambda _e, c=card: c.configure(border_color="#3498db"))
            w.bind("<Leave>", lambda _e, c=card: c.configure(border_color="#333333"))

        return card


class LegendPanel(ctk.CTkFrame):
    """Side panel displaying the color legend for traffic types."""
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        # Title
        ctk.CTkLabel(
            self, text="Legenda de Tráfego",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(15, 15), padx=15, anchor="w")

        # Active
        self._add_legend_item("Ativo", "#ffffff", "Navegação direta.")
        
        # Background
        self._add_legend_item("Standby", "#666666", "Segundo plano (Telemetria, Sincronização, Ping).")
        
        # CDN
        self._add_legend_item("CDN", "#a29bfe", "Anúncios, rastreadores e infraestrutura.")

        # Spacer
        ctk.CTkFrame(self, height=2, fg_color="#333333").pack(fill="x", padx=15, pady=(20, 10))

        # Threat Levels
        ctk.CTkLabel(
            self, text="Ameaças",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(10, 15), padx=15, anchor="w")

        self._add_legend_item("Perigoso", "#e74c3c", "Bloqueado por Blacklist ou regras críticas.")
        self._add_legend_item("Suspeito", "#f39c12", "Comportamento de phishing (ex: Typosquatting).")

    def _add_legend_item(self, title: str, color: str, desc: str):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="x", padx=15, pady=5)
        
        # Color circle/dot
        dot = ctk.CTkLabel(container, text="●", text_color=color, font=ctk.CTkFont(size=18))
        dot.pack(side="left", padx=(0, 10))
        
        text_frame = ctk.CTkFrame(container, fg_color="transparent")
        text_frame.pack(side="left", fill="x", expand=True)
        
        ctk.CTkLabel(
            text_frame, text=title, text_color=color,
            font=ctk.CTkFont(size=12, weight="bold"), anchor="w"
        ).pack(fill="x")
        
        ctk.CTkLabel(
            text_frame, text=desc, text_color="#888888",
            font=ctk.CTkFont(size=11), anchor="w", justify="left"
        ).pack(fill="x")
