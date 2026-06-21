import json
import re
import tkinter as tk
import unicodedata
from datetime import datetime
from tkinter import ttk, filedialog, messagebox

import customtkinter as ctk

from models import DNSEvent, ThreatLevel


class ListManagerDialog(ctk.CTkToplevel):

    _MAX_VISIBLE = 1000

    def __init__(self, master, *, list_type: str, title: str,
                 accent_color: str, checker, on_change: callable = None, **kwargs):
        super().__init__(master, **kwargs)
        self._list_type = list_type
        self._accent = accent_color
        self._checker = checker
        self._on_change = on_change
        self._all_domains: list[str] = []

        self.title(title)
        self.geometry("520x600")
        self.minsize(420, 480)
        self.configure(fg_color="#1a1a1a")

        # Keep the dialog above the main window and grab focus.
        self.transient(master)
        self.after(10, self._grab)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # === Header ===
        header = ctk.CTkLabel(
            self, text=title,
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=accent_color, anchor="w",
        )
        header.grid(row=0, column=0, padx=20, pady=(18, 0), sticky="w")

        self.count_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=11), text_color="#888888", anchor="w",
        )
        self.count_label.grid(row=1, column=0, padx=20, pady=(0, 8), sticky="w")

        # === Search ===
        search_frame = ctk.CTkFrame(self, fg_color="transparent")
        search_frame.grid(row=2, column=0, padx=20, pady=(0, 8), sticky="ew")
        search_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            search_frame, text="🔍  Buscar",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#a0a0a0", anchor="w",
        ).grid(row=0, column=0, pady=(0, 2), sticky="w")

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_list())
        search_entry = ctk.CTkEntry(
            search_frame, textvariable=self.search_var,
            placeholder_text="buscar...",
            height=36,
        )
        search_entry.grid(row=1, column=0, sticky="ew")

        # === Listbox (native tk for performance with large lists) ===
        list_frame = ctk.CTkFrame(self, fg_color="#2b2b2b", corner_radius=8)
        list_frame.grid(row=3, column=0, padx=20, pady=(0, 8), sticky="nsew")
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)

        self.listbox = tk.Listbox(
            list_frame,
            bg="#2b2b2b", fg="#e0e0e0",
            selectbackground=accent_color, selectforeground="#ffffff",
            highlightthickness=0, borderwidth=0,
            font=("Segoe UI", 10), activestyle="none",
        )
        self.listbox.grid(row=0, column=0, padx=(8, 0), pady=8, sticky="nsew")

        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.listbox.yview)
        scrollbar.grid(row=0, column=1, padx=(0, 4), pady=8, sticky="ns")
        self.listbox.configure(yscrollcommand=scrollbar.set)

        # === Add row (label + centered input) ===
        add_frame = ctk.CTkFrame(self, fg_color="transparent")
        add_frame.grid(row=4, column=0, padx=20, pady=(0, 6), sticky="ew")
        add_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            add_frame, text="Insira URL ou IP:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#a0a0a0",
        ).grid(row=0, column=0, pady=(0, 4))

        self.add_var = ctk.StringVar()
        add_entry = ctk.CTkEntry(
            add_frame, textvariable=self.add_var,
            placeholder_text="exemplo.com", height=36, width=320,
            justify="center",
        )
        add_entry.grid(row=1, column=0)
        add_entry.bind("<Return>", lambda _e: self._add_domain())

        # === Action row (three buttons below the input) ===
        action_frame = ctk.CTkFrame(self, fg_color="transparent")
        action_frame.grid(row=5, column=0, padx=20, pady=(8, 18))

        ctk.CTkButton(
            action_frame, text="➕  Adicionar", width=150, height=36,
            fg_color="#4caf50", hover_color="#43a047",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._add_domain,
        ).grid(row=0, column=0, padx=5)

        ctk.CTkButton(
            action_frame, text="🗑  Remover Selecionado", width=200, height=36,
            fg_color="#e74c3c", hover_color="#c0392b",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._remove_selected,
        ).grid(row=0, column=1, padx=5)

        ctk.CTkButton(
            action_frame, text="Fechar", width=110, height=36,
            fg_color="#34495e", hover_color="#2c3e50",
            font=ctk.CTkFont(size=12),
            command=self.destroy,
        ).grid(row=0, column=2, padx=5)

        self._reload_domains()

    # ------------------------------------------------------------------

    def _grab(self):
        try:
            self.grab_set()
            self.focus()
        except tk.TclError:
            pass

    def _reload_domains(self):
        """Pull the full domain list from the checker, then refresh view."""
        self._all_domains = self._checker.get_domains(self._list_type)
        self._refresh_list()

    def _refresh_list(self):
        """Re-render the listbox honoring the current search filter."""
        query = self.search_var.get().strip().lower()
        if query:
            matches = [d for d in self._all_domains if query in d]
        else:
            matches = self._all_domains

        total = len(self._all_domains)
        shown = matches[: self._MAX_VISIBLE]

        self.listbox.delete(0, tk.END)
        for domain in shown:
            self.listbox.insert(tk.END, domain)

        if len(matches) > self._MAX_VISIBLE:
            note = (f"Mostrando {self._MAX_VISIBLE} de {len(matches)} "
                    f"resultados — refine a busca. Total: {total}")
        elif query:
            note = f"{len(matches)} resultado(s) — Total na lista: {total}"
        else:
            note = f"{total} domínio(s) na lista"
        self.count_label.configure(text=note)

    def _add_domain(self):
        raw = self.add_var.get().strip()
        if not raw:
            return
        if self._checker.add_domain(raw, self._list_type):
            self.add_var.set("")
            # on_change recarrega as listas do disco por completo; só então
            # atualizamos a exibição a partir da lista recarregada.
            if self._on_change:
                self._on_change()
            self._reload_domains()
        else:
            messagebox.showinfo(
                "Adicionar",
                "Domínio inválido ou já presente na lista.",
                parent=self,
            )

    def _remove_selected(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showinfo(
                "Remover", "Selecione um domínio na lista para remover.",
                parent=self,
            )
            return
        domain = self.listbox.get(selection[0])
        if not messagebox.askyesno(
            "Remover", f"Remover '{domain}' da lista?", parent=self
        ):
            return
        if self._checker.remove_domain(domain, self._list_type):
            if self._on_change:
                self._on_change()
            self._reload_domains()


class ValidationDialog(ctk.CTkToplevel):

    _URL_KEYS = ("dominio", "url", "URL", "domain", "link", "host")
    _LABEL_KEYS = ("rotulo_real", "rotulo", "label", "tipo", "verdict")
    _PHISHING_VALUES = {
        "phishing", "phish", "malicious", "malware", "bad", "perigoso",
        "malicioso", "suspeito", "1", "true", "sim",
    }
    _GRUPO_PT = {
        ThreatLevel.SAFE: "seguro",
        ThreatLevel.SUSPICIOUS: "suspeito",
        ThreatLevel.MALICIOUS: "perigoso",
    }

    def __init__(self, master, *, classifier, accent_color="#9b59b6", **kwargs):
        super().__init__(master, **kwargs)
        self._classifier = classifier
        self._accent = accent_color
        self._results: list[dict] = []

        self.title("🔮 Validação de URLs")
        self.geometry("620x620")
        self.minsize(500, 520)
        self.configure(fg_color="#1a1a1a")
        self.transient(master)
        self.after(10, self._grab)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)   # input textbox
        self.grid_rowconfigure(8, weight=2)   # results table

        # === Header + description ===
        ctk.CTkLabel(
            self, text="🔮  Validação de URLs",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=accent_color, anchor="w",
        ).grid(row=0, column=0, padx=20, pady=(18, 0), sticky="w")

        ctk.CTkLabel(
            self,
            text="Coloque a URL ou uma lista de domínios que deseja consultar.\n"
                 "Pode ser um domínio direto (ex: www.youtube.com), vários (um por "
                 "linha) ou JSON com o campo \"dominio\" "
                 "(e opcionalmente \"rotulo_real\" para medir acurácia).",
            font=ctk.CTkFont(size=12), text_color="#a0a0a0",
            anchor="w", justify="left",
        ).grid(row=1, column=0, padx=20, pady=(2, 8), sticky="w")

        # === Top buttons ===
        top_btns = ctk.CTkFrame(self, fg_color="transparent")
        top_btns.grid(row=2, column=0, padx=20, pady=(0, 6), sticky="ew")

        ctk.CTkButton(
            top_btns, text="📂  Carregar arquivo (.txt / .json)", height=34, width=240,
            fg_color="#34495e", hover_color="#2c3e50",
            command=self._load_file,
        ).grid(row=0, column=0, padx=(0, 8))

        ctk.CTkButton(
            top_btns, text="🗑  Limpar", height=34, width=110,
            fg_color="#7f8c8d", hover_color="#636e72",
            command=self._clear,
        ).grid(row=0, column=1)

        # === JSON input ===
        self.input_box = ctk.CTkTextbox(
            self, height=200, font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#2b2b2b", border_width=1, border_color="#404040",
        )
        self.input_box.grid(row=3, column=0, padx=20, pady=(0, 8), sticky="nsew")
        self.input_box.insert(
            "1.0",
            '[\n  {"dominio": "exemplo.com", "rotulo_real": "legitimo"},\n'
            '  {"dominio": "paypal-login-verify.tk", "rotulo_real": "phishing"}\n]',
        )

        # === "ou digite a URL" separator + single-line entry ===
        ctk.CTkLabel(
            self, text="── ou digite a URL ──",
            font=ctk.CTkFont(size=12, weight="bold"), text_color="#888888",
        ).grid(row=4, column=0, padx=20, pady=(2, 4))

        self.url_entry = ctk.CTkEntry(
            self, placeholder_text="ex: www.youtube.com", height=36,
        )
        self.url_entry.grid(row=5, column=0, padx=20, pady=(0, 8), sticky="ew")
        self.url_entry.bind("<Return>", lambda _e: self._evaluate())

        # === Evaluate button ===
        ctk.CTkButton(
            self, text="🔮  Avaliar", height=40,
            fg_color=accent_color, hover_color="#8e44ad",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._evaluate,
        ).grid(row=6, column=0, padx=20, pady=(0, 8), sticky="ew")

        # === Summary line ===
        self.summary_label = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=12), text_color="#dddddd",
            anchor="w", justify="left", wraplength=700,
        )
        self.summary_label.grid(row=7, column=0, padx=20, pady=(0, 6), sticky="w")

        # === Results table ===
        table_frame = ctk.CTkFrame(self, fg_color="#2b2b2b", corner_radius=8)
        table_frame.grid(row=8, column=0, padx=20, pady=(0, 8), sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        cols = ("dominio", "grupo", "score", "detalhe")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=10)
        self.tree.heading("dominio", text="Domínio")
        self.tree.heading("grupo", text="Grupo")
        self.tree.heading("score", text="Score")
        self.tree.heading("detalhe", text="Detalhe")
        self.tree.column("dominio", width=200, minwidth=120)
        self.tree.column("grupo", width=80, minwidth=60, anchor="center")
        self.tree.column("score", width=55, minwidth=45, anchor="center")
        self.tree.column("detalhe", width=320, minwidth=150)
        self.tree.grid(row=0, column=0, padx=(8, 0), pady=8, sticky="nsew")
        self.tree.tag_configure("seguro", foreground="#2ecc71")
        self.tree.tag_configure("suspeito", foreground="#f39c12")
        self.tree.tag_configure("perigoso", foreground="#e74c3c")

        tree_scroll = tk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        tree_scroll.grid(row=0, column=1, padx=(0, 4), pady=8, sticky="ns")
        self.tree.configure(yscrollcommand=tree_scroll.set)

        # === Bottom buttons ===
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.grid(row=9, column=0, padx=20, pady=(0, 18), sticky="ew")
        bottom.grid_columnconfigure(0, weight=1)

        self.btn_save = ctk.CTkButton(
            bottom, text="💾  Salvar resultado (JSON)", height=36,
            fg_color="#5dade2", hover_color="#3498db",
            text_color="#15324a", text_color_disabled="#15324a",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._save_result, state="disabled",
        )
        self.btn_save.grid(row=0, column=0, padx=(0, 8), sticky="ew")

        ctk.CTkButton(
            bottom, text="Fechar", width=110, height=36,
            fg_color="#34495e", hover_color="#2c3e50",
            command=self.destroy,
        ).grid(row=0, column=1)

    # ------------------------------------------------------------------

    def _grab(self):
        try:
            self.grab_set()
            self.focus()
        except tk.TclError:
            pass

    @staticmethod
    def _strip_accents(text: str) -> str:
        return "".join(
            c for c in unicodedata.normalize("NFD", text)
            if unicodedata.category(c) != "Mn"
        )

    @staticmethod
    def _normalize_domain(value: str) -> str:
        domain = value.strip().lower()
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0].split(":")[0]
        return domain.strip(".")

    @classmethod
    def _extract(cls, record, keys):
        """Return the first present key value from a dict, else None."""
        if isinstance(record, dict):
            for k in keys:
                if k in record:
                    return record[k]
        return None

    def _load_file(self):
        path = filedialog.askopenfilename(
            parent=self,
            title="Selecione o arquivo com os domínios (JSON)",
            filetypes=[("Texto/JSON", "*.txt *.json"), ("Todos", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as exc:
            messagebox.showerror("Carregar", f"Não foi possível ler o arquivo:\n{exc}", parent=self)
            return
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", content)

    def _clear(self):
        self.input_box.delete("1.0", "end")
        self.url_entry.delete(0, "end")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.summary_label.configure(text="")
        self._results = []
        self.btn_save.configure(state="disabled")

    def _parse_records(self, raw: str) -> list:

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # Plain text fallback: split into individual domains
            tokens = re.split(r"[\s,;]+", raw.strip())
            return [t for t in tokens if t]

        if isinstance(data, str):
            return [data]
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    return value
            # single record object
            return [data]
        raise ValueError("JSON deve ser uma lista de domínios ou de objetos.")

    def _evaluate(self):
        # The single URL field takes precedence when filled.
        url_single = self.url_entry.get().strip()
        raw = url_single if url_single else self.input_box.get("1.0", "end").strip()
        if not raw:
            messagebox.showinfo(
                "Avaliar", "Digite uma URL ou cole/carregue o JSON primeiro.",
                parent=self,
            )
            return
        try:
            records = self._parse_records(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            messagebox.showerror("JSON inválido", f"Não foi possível interpretar o JSON:\n{exc}", parent=self)
            return
        if not records:
            messagebox.showinfo("Avaliar", "Nenhum registro encontrado no JSON.", parent=self)
            return

        for item in self.tree.get_children():
            self.tree.delete(item)
        self._results = []

        fixed_time = datetime(2026, 1, 1)
        tp = fp = tn = fn = 0
        has_labels = False
        evaluated = skipped = 0

        for record in records:
            raw_url = record if isinstance(record, str) else self._extract(record, self._URL_KEYS)
            domain = self._normalize_domain(str(raw_url or ""))
            if not domain:
                skipped += 1
                continue

            event = DNSEvent(
                timestamp=fixed_time, domain=domain, query_type="A",
                src_ip="0.0.0.0", dst_ip="0.0.0.0",
            )
            result = self._classifier.classify(event)
            grupo = self._GRUPO_PT[result.threat_level]
            detalhe = "; ".join(result.reasons) or "Nenhum indicador de risco"

            self.tree.insert(
                "", "end",
                values=(domain, grupo, result.total_score, detalhe),
                tags=(grupo,),
            )
            self._results.append({
                "dominio": domain,
                "rotulo_real": self._extract(record, self._LABEL_KEYS) or "",
                "score": result.total_score,
                "grupo": grupo,
                "detalhe": detalhe,
            })
            evaluated += 1

            # Metrics (only when a real label is present)
            raw_label = self._extract(record, self._LABEL_KEYS)
            if raw_label is not None and str(raw_label).strip() != "":
                has_labels = True
                truth_phishing = self._strip_accents(str(raw_label).strip().lower()) in self._PHISHING_VALUES
                pred_threat = result.threat_level in (ThreatLevel.SUSPICIOUS, ThreatLevel.MALICIOUS)
                if truth_phishing and pred_threat:
                    tp += 1
                elif truth_phishing and not pred_threat:
                    fn += 1
                elif not truth_phishing and pred_threat:
                    fp += 1
                else:
                    tn += 1

        self.btn_save.configure(state="normal" if self._results else "disabled")
        self._show_summary(evaluated, skipped, has_labels, tp, fp, tn, fn)

    def _show_summary(self, evaluated, skipped, has_labels, tp, fp, tn, fn):
        base = f"✅ {evaluated} domínio(s) avaliado(s)"
        if skipped:
            base += f"  •  {skipped} ignorado(s) (sem domínio)"

        if has_labels:
            total = tp + fp + tn + fn
            div = lambda a, b: (a / b) if b else 0.0
            acc = div(tp + tn, total)
            prec = div(tp, tp + fp)
            rec = div(tp, tp + fn)
            f1 = div(2 * prec * rec, prec + rec)
            base += (
                f"\n📊 Métricas (vs. rotulo_real) — "
                f"Acurácia {acc:.1%} | Precisão {prec:.1%} | "
                f"Recall {rec:.1%} | F1 {f1:.1%}"
                f"\n   Matriz: TP={tp}  FP={fp}  FN={fn}  TN={tn}"
            )
        self.summary_label.configure(text=base)

    def _save_result(self):
        if not self._results:
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Todos", "*.*")],
            initialfile=f"validacao_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._results, f, indent=2, ensure_ascii=False)
        messagebox.showinfo("Salvar", f"Resultado salvo em:\n{path}", parent=self)


class DangerPopup(ctk.CTkToplevel):
    """
    Pop-up de alerta exibido quando um domínio PERIGOSO é detectado durante
    a captura ao vivo. Visual vermelho, modal e sempre no topo.
    """

    def __init__(self, master, *, domain: str, score: int, reasons: list[str],
                 on_kill_browsers: callable = None, **kwargs):
        super().__init__(master, **kwargs)
        self._on_kill_browsers = on_kill_browsers
        self.title("🚨 PERIGO — Phishing detectado")
        self.geometry("520x440")
        self.minsize(440, 380)
        self.configure(fg_color="#2b0a0a")
        self.transient(master)

        # Sempre visível e no topo, com alerta sonoro.
        self.lift()
        self.attributes("-topmost", True)
        self.after(10, self._grab)
        try:
            self.bell()
        except tk.TclError:
            pass

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(
            self, text="🚨  PERIGO",
            font=ctk.CTkFont(size=30, weight="bold"), text_color="#ff4d4d",
        ).grid(row=0, column=0, padx=20, pady=(22, 0))

        ctk.CTkLabel(
            self, text="Domínio perigoso detectado durante a captura.\n"
                       "A captura foi interrompida por segurança.",
            font=ctk.CTkFont(size=13), text_color="#ffd6d6", justify="center",
        ).grid(row=1, column=0, padx=20, pady=(4, 12))

        info = ctk.CTkFrame(self, fg_color="#3d1414", corner_radius=10)
        info.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        info.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            info, text=f"🌐  {domain}",
            font=ctk.CTkFont(size=15, weight="bold"), text_color="#ffffff",
            anchor="w", wraplength=420,
        ).grid(row=0, column=0, padx=14, pady=(12, 2), sticky="w")
        ctk.CTkLabel(
            info, text=f"Pontuação de risco: {score}/100",
            font=ctk.CTkFont(size=12), text_color="#ff9999", anchor="w",
        ).grid(row=1, column=0, padx=14, pady=(0, 12), sticky="w")

        reasons_text = "\n".join(f"•  {r}" for r in reasons) or "•  Classificado como perigoso."
        reasons_box = ctk.CTkTextbox(
            self, fg_color="#1f0808", border_width=0,
            font=ctk.CTkFont(size=11), text_color="#ffcccc",
        )
        reasons_box.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="nsew")
        reasons_box.insert("1.0", f"Motivos:\n{reasons_text}")
        reasons_box.configure(state="disabled")

        # === Ações (2 botões) ===
        ctk.CTkButton(
            self, text="🛑  Encerrar navegadores", height=44,
            fg_color="#c0392b", hover_color="#922b21",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._kill_browsers,
        ).grid(row=4, column=0, padx=20, pady=(0, 8), sticky="ew")

        ctk.CTkButton(
            self, text="OK", height=38,
            fg_color="#34495e", hover_color="#2c3e50",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.destroy,
        ).grid(row=5, column=0, padx=20, pady=(0, 18), sticky="ew")

    def _kill_browsers(self):
        """Dispara o encerramento dos navegadores (e a pergunta de reinício)."""
        if self._on_kill_browsers:
            self._on_kill_browsers()

    def _grab(self):
        try:
            self.grab_set()
            self.focus()
        except tk.TclError:
            pass


class StatCard(ctk.CTkFrame):

    def __init__(self, master, title: str, value: str = "0",
                 accent_color: str = "#3498db", **kwargs):
        super().__init__(master, corner_radius=12, **kwargs)

        self._accent = accent_color
        self._on_click = None

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

    def set_on_click(self, callback: callable):
        """Make the card clickable (used to filter the event table)."""
        self._on_click = callback
        for w in (self, self.title_label, self.value_label):
            w.configure(cursor="hand2")
            w.bind("<Button-1>", lambda _e: self._on_click and self._on_click())

    def set_selected(self, selected: bool):
        """Highlight the card with a colored border when it is the active filter."""
        self.configure(
            border_width=2 if selected else 0,
            border_color=self._accent,
        )


class EventDetailPanel(ctk.CTkFrame):

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
            font=ctk.CTkFont(size=17, weight="bold")
        ).pack(pady=(12, 8), padx=15, anchor="w")

        # Active
        self._add_legend_item("Ativo", "#ffffff", "Navegação direta.")
        
        # Background
        self._add_legend_item("Standby", "#666666", "Segundo plano, telemetria e ping.")
        
        # CDN
        self._add_legend_item("CDN", "#a29bfe", "Anúncios, rastreadores e infraestrutura.")

        # Socket/cache
        self._add_legend_item(
            "Requisição registrada localmente",
            "#74b9ff",
            "Resposta DNS ou entrada do cache/socket local.",
        )

        # Spacer
        ctk.CTkFrame(self, height=2, fg_color="#333333").pack(fill="x", padx=15, pady=(12, 8))

        # Threat Levels
        ctk.CTkLabel(
            self, text="Ameaças",
            font=ctk.CTkFont(size=17, weight="bold")
        ).pack(pady=(6, 8), padx=15, anchor="w")

        self._add_legend_item("Perigoso", "#e74c3c", "Bloqueado por Blacklist ou regras críticas.")
        self._add_legend_item("Suspeito", "#f39c12", "Comportamento de phishing (ex: Typosquatting).")

    def _add_legend_item(self, title: str, color: str, desc: str):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(fill="x", padx=15, pady=3)
        
        # Color circle/dot
        dot = ctk.CTkLabel(container, text="●", text_color=color, font=ctk.CTkFont(size=16))
        dot.pack(side="left", padx=(0, 8))
        
        text_frame = ctk.CTkFrame(container, fg_color="transparent")
        text_frame.pack(side="left", fill="x", expand=True)
        
        ctk.CTkLabel(
            text_frame, text=title, text_color=color,
            font=ctk.CTkFont(size=12, weight="bold"), anchor="w"
        ).pack(fill="x")
        
        ctk.CTkLabel(
            text_frame, text=desc, text_color="#888888",
            font=ctk.CTkFont(size=10), anchor="w", justify="left", wraplength=250
        ).pack(fill="x")
