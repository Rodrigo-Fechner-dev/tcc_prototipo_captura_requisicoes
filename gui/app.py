"""
PhishGuard — Main GUI Application

The main application window built with CustomTkinter.
Provides real-time DNS monitoring with visual threat classification.

Layout:
    ┌─────────────────────────────────────────────────────┐
    │  [Stats Cards: Total | Seguro | Suspeito | Perigoso]│
    ├───────────────────────────────┬─────────────────────┤
    │  Event Table (Treeview)       │  Event Detail Panel  │
    │  - Hora                       │  - Domínio           │
    │  - Domínio                    │  - Status            │
    │  - IP Origem                  │  - Score             │
    │  - Status                     │  - Motivos           │
    │                               │  - Recomendação      │
    ├───────────────────────────────┴─────────────────────┤
    │  [▶ Iniciar] [⏹ Parar] [🗑 Limpar] [📥 Exportar]   │
    ├─────────────────────────────────────────────────────┤
    │  Status Bar                                         │
    └─────────────────────────────────────────────────────┘
"""

import queue
import json
import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

import customtkinter as ctk

from config import config
from models import AnalysisResult, ThreatLevel, TrafficType
from sniffer.capture import DNSCapture
from analyzer.classifier import ThreatClassifier
from gui.widgets import StatCard, StatusBar, InterfaceSelectorFrame, LegendPanel

logger = logging.getLogger(__name__)


class PhishGuardApp(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        # Window setup
        self.title(config.gui.title)
        self.geometry(f"{config.gui.width}x{config.gui.height}")
        self.minsize(900, 600)

        # Set dark theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Core components (initialized after interface selection)
        self.event_queue: queue.Queue | None = None
        self.dns_capture: DNSCapture | None = None
        self.classifier: ThreatClassifier | None = None
        self._results: list[AnalysisResult] = []
        self._cache_results: list[dict] = []
        self._seen_cache_domains: set[str] = set()
        self._selected_interface: str | None = None
        self._capture_started_at: datetime | None = None
        self._capture_start_stats: dict[str, int] = {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "malicious": 0,
        }
        self._capture_start_cache_count = 0

        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Show interface selector as first screen
        self._show_interface_selector()

    # ------------------------------------------------------------------
    # Interface selection flow
    # ------------------------------------------------------------------

    def _show_interface_selector(self):
        """Display the network interface selection screen."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._selector = InterfaceSelectorFrame(
            self, on_select=self._on_interface_selected,
        )
        self._selector.grid(row=0, column=0, sticky="nsew")

    def _on_interface_selected(self, interface_name: str):
        """Callback when user picks an interface — bootstrap the main app."""
        self._selected_interface = interface_name
        self._selector.destroy()

        # Initialize core components with the chosen interface
        self.event_queue = queue.Queue(maxsize=10000)
        self.dns_capture = DNSCapture(self.event_queue, interface=interface_name)
        self.classifier = ThreatClassifier()

        # Reset grid weights for main layout
        self.grid_rowconfigure(0, weight=0)

        # Build the main dashboard
        self._build_layout()
        self._configure_treeview_style()

        # Update status bar with context
        self.status_bar.set_blacklist_info(self.classifier.blacklist.blacklist_count)
        self.status_bar.info_label.configure(
            text=f"PhishGuard MVP — Interface: {interface_name}",
        )

        # Start GUI polling loop
        self._poll_events()
        logger.info("Interface selected: %s", interface_name)

    def _build_layout(self):
        """Construct all UI elements."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # === Row 0: Stats Cards ===
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.grid(row=0, column=0, padx=15, pady=(15, 5), sticky="ew")
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.card_total = StatCard(
            stats_frame, title="📡 TOTAL", accent_color="#3498db"
        )
        self.card_total.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.card_safe = StatCard(
            stats_frame, title="🟢 SEGURO", accent_color="#2ecc71"
        )
        self.card_safe.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.card_suspicious = StatCard(
            stats_frame, title="🟡 SUSPEITO", accent_color="#f39c12"
        )
        self.card_suspicious.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        self.card_malicious = StatCard(
            stats_frame, title="🔴 PERIGOSO", accent_color="#e74c3c"
        )
        self.card_malicious.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        # === Row 1: Main Content (Table + Detail Panel) ===
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.grid(row=1, column=0, padx=15, pady=5, sticky="nsew")
        content_frame.grid_columnconfigure(0, weight=3) # Table
        content_frame.grid_columnconfigure(1, weight=0) # Legend Panel
        content_frame.grid_rowconfigure(0, weight=1)

        # Event Table (left side)
        table_frame = ctk.CTkFrame(content_frame, corner_radius=12)
        table_frame.grid(row=0, column=0, padx=(0, 5), sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(2, weight=1)

        # Table header
        table_header = ctk.CTkLabel(
            table_frame, text="📋 Eventos de DNS em Tempo Real",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        table_header.grid(row=0, column=0, padx=15, pady=(12, 5), sticky="w")

        self.event_tabs = ctk.CTkSegmentedButton(
            table_frame,
            values=["Ativo", "Background", "Socket/Cache"],
            command=self._switch_event_tab,
        )
        self.event_tabs.grid(row=1, column=0, padx=15, pady=(0, 8), sticky="w")
        self.event_tabs.set("Ativo")

        # Treeviews for event logs
        columns = ("hora", "dominio", "tipo", "ip_origem", "status")
        self.active_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            selectmode="browse", height=20,
        )
        self.background_tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            selectmode="browse", height=20,
        )

        cache_columns = ("hora", "dominio", "tipo", "origem", "resposta")
        self.cache_tree = ttk.Treeview(
            table_frame, columns=cache_columns, show="headings",
            selectmode="browse", height=20,
        )

        for tree in (self.active_tree, self.background_tree):
            tree.heading("hora", text="Hora")
            tree.heading("dominio", text="Domínio")
            tree.heading("tipo", text="Tipo")
            tree.heading("ip_origem", text="IP Origem")
            tree.heading("status", text="Status")

            tree.column("hora", width=80, minwidth=60)
            tree.column("dominio", width=300, minwidth=150)
            tree.column("tipo", width=50, minwidth=40)
            tree.column("ip_origem", width=120, minwidth=80)
            tree.column("status", width=100, minwidth=80)

        self.cache_tree.heading("hora", text="Hora")
        self.cache_tree.heading("dominio", text="Domínio")
        self.cache_tree.heading("tipo", text="Tipo")
        self.cache_tree.heading("origem", text="Origem")
        self.cache_tree.heading("resposta", text="Resposta")

        self.cache_tree.column("hora", width=80, minwidth=60)
        self.cache_tree.column("dominio", width=260, minwidth=150)
        self.cache_tree.column("tipo", width=60, minwidth=45)
        self.cache_tree.column("origem", width=110, minwidth=80)
        self.cache_tree.column("resposta", width=220, minwidth=120)

        self.tree = self.active_tree
        self.active_tree.grid(row=2, column=0, padx=5, pady=(0, 5), sticky="nsew")

        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self._scroll_current_tree)
        scrollbar.grid(row=2, column=1, sticky="ns", pady=(0, 5))
        self.scrollbar = scrollbar
        for tree in (self.active_tree, self.background_tree, self.cache_tree):
            tree.configure(yscrollcommand=scrollbar.set)

        # Legend Panel (right side)
        self.legend_panel = LegendPanel(content_frame, width=330)
        self.legend_panel.grid(row=0, column=1, padx=(10, 0), sticky="ns")
        self.legend_panel.grid_propagate(False)

        # === Row 2: Control Buttons ===
        controls_frame = ctk.CTkFrame(self, fg_color="transparent")
        controls_frame.grid(row=2, column=0, padx=15, pady=5, sticky="ew")

        self.btn_start = ctk.CTkButton(
            controls_frame, text="▶  Iniciar Captura",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#2ecc71", hover_color="#27ae60",
            command=self._start_capture, width=180,
        )
        self.btn_start.grid(row=0, column=0, padx=5, pady=5)

        self.btn_stop = ctk.CTkButton(
            controls_frame, text="⏹  Parar",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#e74c3c", hover_color="#c0392b",
            command=self._stop_capture, width=130,
            state="disabled",
        )
        self.btn_stop.grid(row=0, column=1, padx=5, pady=5)

        self.btn_clear = ctk.CTkButton(
            controls_frame, text="🗑  Limpar",
            font=ctk.CTkFont(size=13),
            fg_color="#7f8c8d", hover_color="#636e72",
            command=self._clear_events, width=130,
        )
        self.btn_clear.grid(row=0, column=2, padx=5, pady=5)

        self.btn_export = ctk.CTkButton(
            controls_frame, text="📥  Exportar",
            font=ctk.CTkFont(size=13),
            fg_color="#3498db", hover_color="#2980b9",
            command=self._export_events, width=130,
        )
        self.btn_export.grid(row=0, column=3, padx=5, pady=5)

        # === Row 3: Status Bar ===
        self.status_bar = StatusBar(self)
        self.status_bar.grid(row=3, column=0, sticky="ew")

    def _configure_treeview_style(self):
        """Style the ttk.Treeview to match the dark theme."""
        style = ttk.Style()
        style.theme_use("clam")

        # Treeview colors
        style.configure("Treeview",
            background="#2b2b2b",
            foreground="#e0e0e0",
            fieldbackground="#2b2b2b",
            rowheight=28,
            font=("Segoe UI", 10),
        )
        style.configure("Treeview.Heading",
            background="#1a1a2e",
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
        )
        style.map("Treeview",
            background=[("selected", "#1a5276")],
            foreground=[("selected", "#ffffff")],
        )

        for tree in (self.active_tree, self.background_tree, self.cache_tree):
            # Tag colors for traffic types (used for SAFE traffic)
            tree.tag_configure("active", foreground="#ffffff")
            tree.tag_configure("background", foreground="#a0a0a0")
            tree.tag_configure("cdn", foreground="#a29bfe")
            tree.tag_configure("cache", foreground="#74b9ff")

            # Tag colors for threat levels (these take precedence for threats)
            tree.tag_configure("suspicious", foreground="#f39c12", background="#3d3520")
            tree.tag_configure("malicious", foreground="#e74c3c", background="#3d2020")

    def _poll_events(self):
        """Poll the event queue and process new DNS events."""
        processed = 0
        max_per_cycle = 50  # Limit to keep GUI responsive

        while processed < max_per_cycle:
            try:
                event = self.event_queue.get_nowait()
            except queue.Empty:
                break

            if event.event_type == "query":
                result = self.classifier.classify(event)
                self._add_event_to_table(result)
                self._results.append(result)
            elif event.event_type == "response":
                self._add_cache_event(event.domain, event.query_type, "Resposta DNS", event.answers)
            processed += 1

        # Update stats cards
        stats = self.classifier.get_stats()
        self.card_total.update_value(stats["total"])
        self.card_safe.update_value(stats["safe"])
        self.card_suspicious.update_value(stats["suspicious"])
        self.card_malicious.update_value(stats["malicious"])

        # Update status bar
        if self.dns_capture.is_running:
            self.status_bar.set_running(self.dns_capture.packet_count)

        # Schedule next poll
        self.after(config.gui.update_interval_ms, self._poll_events)

    def _add_event_to_table(self, result: AnalysisResult):
        """Add a classified event to the treeview table."""
        event = result.event
        level = result.threat_level

        status_text = f"{level.emoji} {level.label_pt}"
        
        # Determine row color tag
        if level == ThreatLevel.SAFE:
            tag = result.traffic_type.value
        else:
            tag = level.value

        tree = self.active_tree
        if result.traffic_type in (TrafficType.BACKGROUND, TrafficType.CDN):
            tree = self.background_tree

        item_id = tree.insert(
            "", 0,  # Insert at top (newest first)
            values=(
                event.timestamp_str,
                event.domain,
                event.query_type,
                event.src_ip,
                status_text,
            ),
            tags=(tag,),
        )

        # Auto-scroll to top for new events
        if tree is self.tree:
            tree.see(item_id)

        # Limit table size to prevent memory issues
        children = tree.get_children()
        if len(children) > 5000:
            tree.delete(children[-1])

    def _add_cache_event(self, domain: str, query_type: str, source: str, answers: list[str] | None = None):
        """Add a DNS answer or resolver-cache entry to the Socket/Cache tab."""
        normalized = domain.lower().strip(".")
        if not normalized or normalized == "n/a":
            return

        cache_key = f"{source}:{normalized}:{query_type}"
        if source == "Cache Windows" and cache_key in self._seen_cache_domains:
            return
        self._seen_cache_domains.add(cache_key)

        timestamp = datetime.now()
        answer_text = ", ".join(answers or []) or "Resolvido localmente"
        item_id = self.cache_tree.insert(
            "", 0,
            values=(
                timestamp.strftime("%H:%M:%S"),
                domain,
                query_type,
                source,
                answer_text,
            ),
            tags=("cache",),
        )
        self._cache_results.append({
            "timestamp": timestamp.isoformat(),
            "domain": domain,
            "query_type": query_type,
            "source": source,
            "answers": answers or [],
        })

        if self.tree is self.cache_tree:
            self.cache_tree.see(item_id)

        children = self.cache_tree.get_children()
        if len(children) > 5000:
            self.cache_tree.delete(children[-1])

    def _switch_event_tab(self, tab_name: str):
        """Show only the selected DNS event table."""
        selected = {
            "Ativo": self.active_tree,
            "Background": self.background_tree,
            "Socket/Cache": self.cache_tree,
        }[tab_name]

        for tree in (self.active_tree, self.background_tree, self.cache_tree):
            tree.grid_remove()
        selected.grid(row=2, column=0, padx=5, pady=(0, 5), sticky="nsew")
        self.tree = selected
        self.scrollbar.configure(command=self._scroll_current_tree)

    def _scroll_current_tree(self, *args):
        """Route the shared scrollbar to the visible table."""
        self.tree.yview(*args)

    def _load_windows_dns_cache(self):
        """Load entries already present in the Windows DNS resolver cache."""
        try:
            completed = subprocess.run(
                ["ipconfig", "/displaydns"],
                capture_output=True,
                text=True,
                encoding="cp850",
                errors="ignore",
                timeout=5,
                check=False,
            )
        except Exception as exc:
            logger.debug("Could not read Windows DNS cache: %s", exc)
            return

        current_name = ""
        for raw_line in completed.stdout.splitlines():
            line = raw_line.strip()
            name_match = re.search(
                r"(?:Record Name|Nome do Registro)\s*\.\s*:\s*(.+)",
                line,
                re.IGNORECASE,
            )
            if name_match:
                current_name = name_match.group(1).strip().rstrip(".")
                continue

            if not current_name:
                continue

            type_match = re.search(
                r"(?:Record Type|Tipo de Registro)\s*\.\s*:\s*(\d+)",
                line,
                re.IGNORECASE,
            )
            if type_match:
                query_type = {
                    1: "A",
                    5: "CNAME",
                    28: "AAAA",
                }.get(int(type_match.group(1)), type_match.group(1))
                self._add_cache_event(current_name, query_type, "Cache Windows")


    def _start_capture(self):
        """Start DNS packet capture."""
        try:
            self.dns_capture.start()
            self._capture_started_at = datetime.now()
            self._capture_start_stats = self.classifier.get_stats()
            self._capture_start_cache_count = len(self._cache_results)
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")
            self.status_bar.set_running()
            logger.info("Capture started by user")
        except Exception as e:
            messagebox.showerror(
                "Erro ao Iniciar",
                f"Não foi possível iniciar a captura.\n\n"
                f"Verifique se:\n"
                f"• O programa está rodando como Administrador\n"
                f"• O Npcap está instalado corretamente\n\n"
                f"Erro: {e}"
            )

    def _stop_capture(self):
        """Stop DNS packet capture."""
        self.dns_capture.stop()
        self._write_capture_summary()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.status_bar.set_stopped()
        logger.info("Capture stopped by user")

    def _clear_events(self):
        """Clear all events from the table."""
        for tree in (self.active_tree, self.background_tree, self.cache_tree):
            for item in tree.get_children():
                tree.delete(item)
        self._results.clear()
        self._cache_results.clear()
        self._seen_cache_domains.clear()
        self.classifier.reset_stats()
        if self.dns_capture and self.dns_capture.is_running:
            self._capture_started_at = datetime.now()
            self._capture_start_stats = self.classifier.get_stats()
            self._capture_start_cache_count = 0
        self.card_total.update_value(0)
        self.card_safe.update_value(0)
        self.card_suspicious.update_value(0)
        self.card_malicious.update_value(0)
        logger.info("Events cleared by user")

    def _export_events(self):
        """Export captured events to a JSON file."""
        if not self._results and not self._cache_results:
            messagebox.showinfo("Exportar", "Nenhum evento para exportar.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Todos", "*.*")],
            initialfile=f"phishguard_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        if not filepath:
            return

        dns_events = []
        for result in self._results:
            dns_events.append({
                "timestamp": result.event.timestamp.isoformat(),
                "domain": result.event.domain,
                "query_type": result.event.query_type,
                "src_ip": result.event.src_ip,
                "dst_ip": result.event.dst_ip,
                "threat_level": result.threat_level.value,
                "score": result.total_score,
                "is_blacklisted": result.is_blacklisted,
                "reasons": result.reasons,
                "recommendation": result.recommendation_pt,
            })

        export_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "interface": self._selected_interface,
                "dns_events": len(dns_events),
                "local_records": len(self._cache_results),
            },
            "dns_events": dns_events,
            "local_records": self._cache_results,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        messagebox.showinfo(
            "Exportar",
            f"✅ {len(dns_events) + len(self._cache_results)} registros exportados para:\n{filepath}"
        )
        logger.info("Exported %d records to %s", len(dns_events) + len(self._cache_results), filepath)

    def _write_capture_summary(self):
        """Write a single compact TXT summary for the latest capture."""
        if not self._capture_started_at or not self.dns_capture:
            return

        current_stats = self.classifier.get_stats()
        stats = {
            key: max(0, current_stats.get(key, 0) - self._capture_start_stats.get(key, 0))
            for key in ("total", "safe", "suspicious", "malicious")
        }
        local_records = max(0, len(self._cache_results) - self._capture_start_cache_count)
        stopped_at = datetime.now()
        log_path = Path(config.log_file)
        log_path.parent.mkdir(exist_ok=True)

        summary = (
            "PhishGuard - Resumo da ultima captura\n"
            f"Data de inicio: {self._capture_started_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Data de termino: {stopped_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Interface: {self._selected_interface or 'N/A'}\n"
            f"Pacotes DNS capturados: {self.dns_capture.packet_count}\n"
            f"Requisicoes analisadas: {stats['total']}\n"
            f"Seguras: {stats['safe']}\n"
            f"Suspeitas: {stats['suspicious']}\n"
            f"Perigosas: {stats['malicious']}\n"
            f"Requisicoes registradas localmente: {local_records}\n"
            "\n"
            "Detalhes dos eventos nao ficam neste log automatico. Use Exportar no programa para salvar os registros completos.\n"
        )
        log_path.write_text(summary, encoding="utf-8")
        logger.info("Capture summary written to %s", log_path)


    def _on_close(self):
        """Clean shutdown on window close."""
        if self.dns_capture and self.dns_capture.is_running:
            self.dns_capture.stop()
            self._write_capture_summary()
        self.destroy()
