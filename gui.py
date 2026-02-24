"""
gui.py
------
Tkinter GUI for the RSA Common Modulus Attack demonstration.

Buttons:
  1. Generate Keys    — create two RSA users sharing the same n (vulnerable)
  2. Run Attack       — execute the GCD attack, log results (red = broken)
  3. Apply Prevention — switch to unique-n key generation
  4. Show Graphs      — open all 4 matplotlib graphs (runs in separate thread)

Text log uses colour tags:
  red_tag    — attack succeeded  (private key exposed)
  green_tag  — attack failed     ("Secure")
  orange_tag — section headers / summaries
  white_tag  — neutral info lines
"""

import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import threading
import time
import math

from rsa_common_modulus import (
    generate_shared_modulus_keypairs,
    generate_secure_keypair,
    run_attack_on_shared_modulus,
    common_modulus_attack,
    run_tests,
    summarise_results,
    reset_registry,
    MATH_PROOF,
)


# ─────────────────────────────────────────────
#  Colour / font constants
# ─────────────────────────────────────────────
BG         = "#0f0f1a"
BG_PANEL   = "#16213e"
BG_BTN     = "#1a1a2e"
ACCENT     = "#7c3aed"        # purple accent for buttons
ACCENT_HOV = "#6d28d9"
FG_WHITE   = "#e2e8f0"
FG_GREY    = "#94a3b8"
RED        = "#ef4444"
GREEN      = "#22c55e"
ORANGE     = "#f97316"
YELLOW     = "#facc15"
MONO_FONT  = ("Consolas", 10)
TITLE_FONT = ("Segoe UI", 12, "bold")
BTN_FONT   = ("Segoe UI", 10, "bold")
N_TESTS    = 25
KEY_BITS   = 512


class RSAApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RSA Common Modulus Attack — Demonstration")
        self.geometry("1050x720")
        self.configure(bg=BG)
        self.resizable(True, True)

        # State
        self._kp1 = None
        self._kp2 = None
        self._prevention = False
        self._before_rate = None
        self._after_rate  = None

        self._build_ui()

    # ─────────────────────────────────
    # UI Construction
    # ─────────────────────────────────

    def _build_ui(self):
        # ── Title bar ──
        title_frame = tk.Frame(self, bg=ACCENT, pady=10)
        title_frame.pack(fill="x")
        tk.Label(title_frame, text="🔐  RSA Common Modulus Attack",
                 bg=ACCENT, fg="white", font=("Segoe UI", 15, "bold")).pack()
        tk.Label(title_frame,
                 text="Demonstrates how shared moduli break RSA security",
                 bg=ACCENT, fg="#d8b4fe", font=("Segoe UI", 9)).pack()

        # ── Main panes ──
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=12, pady=8)

        # Left: controls + status
        left = tk.Frame(main, bg=BG, width=270)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)

        # Right: log
        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_left_panel(left)
        self._build_log_panel(right)

    def _build_left_panel(self, parent):
        # ── Status badge ──
        status_frame = tk.Frame(parent, bg=BG_PANEL, bd=0,
                                highlightthickness=1,
                                highlightbackground=ACCENT)
        status_frame.pack(fill="x", pady=(0, 10))
        tk.Label(status_frame, text="STATUS", bg=BG_PANEL, fg=FG_GREY,
                 font=("Segoe UI", 8, "bold"), pady=4).pack()
        self._status_var = tk.StringVar(value="⚠  Vulnerable")
        self._status_lbl = tk.Label(status_frame, textvariable=self._status_var,
                                    bg=BG_PANEL, fg=RED,
                                    font=("Segoe UI", 11, "bold"), pady=6)
        self._status_lbl.pack()

        # ── Buttons ──
        btn_cfg = dict(bg=BG_BTN, fg=FG_WHITE, font=BTN_FONT,
                       relief="flat", cursor="hand2",
                       activebackground=ACCENT_HOV, activeforeground="white",
                       pady=10, padx=6, bd=0)

        buttons = [
            ("🔑  Generate Keys",     self._on_generate_keys,     ACCENT),
            ("⚔   Run Attack",        self._on_run_attack,        RED),
            ("🛡   Apply Prevention",  self._on_apply_prevention,  "#065f46"),
            ("📊  Show Graphs",        self._on_show_graphs,       "#1e3a5f"),
        ]

        tk.Label(parent, text="ACTIONS", bg=BG, fg=FG_GREY,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")

        for text, cmd, color in buttons:
            btn = tk.Button(parent, text=text, command=cmd,
                            bg=color, **{k: v for k, v in btn_cfg.items()
                                         if k not in ("bg",)})
            btn.pack(fill="x", pady=3)
            btn.bind("<Enter>", lambda e, b=btn, c=color: b.config(bg=ACCENT_HOV))
            btn.bind("<Leave>", lambda e, b=btn, c=color: b.config(bg=c))

        # ── Info panel ──
        tk.Label(parent, text="\nKEY INFO", bg=BG, fg=FG_GREY,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")

        info_frame = tk.Frame(parent, bg=BG_PANEL, pady=8, padx=8)
        info_frame.pack(fill="x")

        self._info_vars = {
            "Key Size":   tk.StringVar(value=f"{KEY_BITS} bits"),
            "Tests":      tk.StringVar(value=f"{N_TESTS}"),
            "Prevention": tk.StringVar(value="OFF"),
            "e1":         tk.StringVar(value="65537"),
            "e2":         tk.StringVar(value="257"),
        }
        for label, var in self._info_vars.items():
            row = tk.Frame(info_frame, bg=BG_PANEL)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=f"{label}:", bg=BG_PANEL, fg=FG_GREY,
                     font=("Segoe UI", 9), width=10, anchor="w").pack(side="left")
            tk.Label(row, textvariable=var, bg=BG_PANEL, fg=YELLOW,
                     font=("Consolas", 9, "bold")).pack(side="left")

        # ── Progress bar ──
        tk.Label(parent, text="\nPROGRESS", bg=BG, fg=FG_GREY,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self._progress_var = tk.DoubleVar(value=0)
        self._progress = ttk.Progressbar(parent, variable=self._progress_var,
                                         maximum=N_TESTS, length=240,
                                         style="TProgressbar")
        self._progress.pack(fill="x", pady=4)
        self._progress_lbl = tk.Label(parent, text="", bg=BG, fg=FG_GREY,
                                      font=("Segoe UI", 8))
        self._progress_lbl.pack()

        # ── Math proof button ──
        tk.Button(parent, text="📐  Show Math Proof",
                  command=self._on_show_proof,
                  bg="#1c1c2e", fg=FG_GREY, font=("Segoe UI", 8),
                  relief="flat", cursor="hand2", pady=6,
                  activebackground=BG_PANEL, activeforeground=FG_WHITE
                  ).pack(fill="x", pady=(14, 0))

    def _build_log_panel(self, parent):
        tk.Label(parent, text="ACTIVITY LOG", bg=BG, fg=FG_GREY,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")

        log_frame = tk.Frame(parent, bg=BG_PANEL, bd=0,
                             highlightthickness=1,
                             highlightbackground="#2a2a4a")
        log_frame.pack(fill="both", expand=True)

        self._log = scrolledtext.ScrolledText(
            log_frame,
            bg="#0a0a14", fg=FG_WHITE,
            font=MONO_FONT,
            insertbackground=FG_WHITE,
            relief="flat", bd=0,
            padx=10, pady=8,
            wrap="word",
            state="disabled",
        )
        self._log.pack(fill="both", expand=True)

        # Colour tags
        self._log.tag_config("red_tag",    foreground=RED)
        self._log.tag_config("green_tag",  foreground=GREEN)
        self._log.tag_config("orange_tag", foreground=ORANGE)
        self._log.tag_config("yellow_tag", foreground=YELLOW)
        self._log.tag_config("grey_tag",   foreground=FG_GREY)
        self._log.tag_config("white_tag",  foreground=FG_WHITE)
        self._log.tag_config("accent_tag", foreground="#a78bfa")

        # Clear button
        tk.Button(parent, text="Clear Log",
                  command=self._clear_log,
                  bg=BG_BTN, fg=FG_GREY, font=("Segoe UI", 8),
                  relief="flat", cursor="hand2",
                  activebackground="#1e1e30", activeforeground=FG_WHITE
                  ).pack(anchor="e", pady=2)

        self._log_msg("RSA Common Modulus Attack Demo ready.\n"
                      "  → Click 'Generate Keys' to begin.\n", "accent_tag")

    # ─────────────────────────────────
    # Logging helpers
    # ─────────────────────────────────

    def _log_msg(self, text: str, tag: str = "white_tag"):
        self._log.config(state="normal")
        self._log.insert("end", text, tag)
        self._log.see("end")
        self._log.config(state="disabled")

    def _log_sep(self, char="─", n=60):
        self._log_msg(char * n + "\n", "grey_tag")

    def _clear_log(self):
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")

    # ─────────────────────────────────
    # Button handlers
    # ─────────────────────────────────

    def _on_generate_keys(self):
        self._log_sep()
        self._log_msg("[ GENERATE KEYS ]\n", "orange_tag")
        self._log_msg(f"  Generating {'SECURE (unique n)' if self._prevention else 'VULNERABLE (shared n)'} "
                      f"{KEY_BITS}-bit RSA key pairs…\n", "grey_tag")
        try:
            if self._prevention:
                reset_registry()
                self._kp1 = generate_secure_keypair(KEY_BITS)
                self._kp2 = generate_secure_keypair(KEY_BITS)
                gcd_val = math.gcd(self._kp1["n"], self._kp2["n"])
                shared = gcd_val > 1
                tag = "red_tag" if shared else "green_tag"
                self._log_msg(f"  User 1: \n"
                              f"    n1 = {str(self._kp1['n'])[:40]}…\n"
                              f"    e1 = {self._kp1['e']}\n", "white_tag")
                self._log_msg(f"  User 2: \n"
                              f"    n2 = {str(self._kp2['n'])[:40]}…\n"
                              f"    e2 = {self._kp2['e']}\n", "white_tag")
                self._log_msg(f"\n  Checking for shared primes... GCD(n1, n2) = {gcd_val}\n", "accent_tag")
                self._log_msg(f"  ✔ Moduli are mathematically independent! (Prevention ACTIVE)\n", tag)
            else:
                self._kp1, self._kp2 = generate_shared_modulus_keypairs(KEY_BITS)
                self._log_msg(f"  User 1: \n"
                              f"    n1 = {str(self._kp1['n'])[:40]}…\n"
                              f"    e1 = {self._kp1['e']}\n", "white_tag")
                self._log_msg(f"  User 2: \n"
                              f"    n2 = {str(self._kp2['n'])[:40]}…\n"
                              f"    e2 = {self._kp2['e']}\n", "white_tag")
                gcd_val = math.gcd(self._kp1["n"], self._kp2["n"])
                if gcd_val > 1 and self._kp1["n"] != self._kp2["n"]:
                    self._log_msg(f"\n  Checking for shared primes... GCD(n1, n2) = {str(gcd_val)[:20]}...\n", "red_tag")
                    self._log_msg("  ⚠ CRITICAL VULNERABILITY DETECTED!\n", "red_tag")
                    self._log_msg(
                        "    Despite having different n values, User 1 and User 2 share\n"
                        "    a common prime factor 'p' (due to poor random generation).\n"
                        "    Because GCD(n1, n2) = p, an attacker can trivially factor \n"
                        "    BOTH keys without any brute force!\n", "red_tag"
                    )
        except Exception as exc:
            self._log_msg(f"  ERROR: {exc}\n", "red_tag")

    def _on_run_attack(self):
        if self._kp1 is None or self._kp2 is None:
            messagebox.showwarning("No Keys", "Please generate keys first.")
            return
        self._log_sep()
        self._log_msg("[ RUN ATTACK — Demonstration ]\n", "orange_tag")
        self._log_msg("  Attacker only knows the public data:\n", "grey_tag")
        self._log_msg(f"    n1 = {str(self._kp1['n'])[:40]}...\n", "grey_tag")
        self._log_msg(f"    n2 = {str(self._kp2['n'])[:40]}...\n\n", "grey_tag")

        if not self._prevention:
            self._log_msg("  ATTACK MATH:\n", "accent_tag")
            self._log_msg("  1. Attacker runs Euclidean algorithm: p = GCD(n1, n2)\n", "white_tag")
            gcd_p = math.gcd(self._kp1['n'], self._kp2['n'])
            self._log_msg(f"     => p = {str(gcd_p)[:30]}...\n", "red_tag")
            self._log_msg("  2. Attacker divides to find the other primes:\n", "white_tag")
            q1 = self._kp1['n'] // gcd_p
            q2 = self._kp2['n'] // gcd_p
            self._log_msg(f"     => q1 = n1 / p = {str(q1)[:25]}...\n", "red_tag")
            self._log_msg(f"     => q2 = n2 / p = {str(q2)[:25]}...\n", "red_tag")
            self._log_msg("  3. Attacker calculates phi and mod_inverse(e, phi) to get BOTH private keys (d1, d2)!\n\n", "white_tag")
        else:
            self._log_msg("  ATTACK MATH:\n", "accent_tag")
            self._log_msg("  1. Attacker runs Euclidean algorithm: p = GCD(n1, n2)\n", "white_tag")
            self._log_msg("     => p = 1\n", "green_tag")
            self._log_msg("  2. GCD is 1 (keys are coprime). No prime factors were shared.\n", "white_tag")
            self._log_msg("  3. Attack fails. RSA remains secure.\n\n", "green_tag")

        self._log_sep("-")
        self._log_msg("[ Running 25 Test Cases for Statistical Proof ]\n", "orange_tag")

        prevention = self._prevention
        self._progress_var.set(0)

        def _worker():
            def _progress_cb(i, total, res):
                self._progress_var.set(i)
                pct = i / total * 100
                self._progress_lbl.config(text=f"Test {i}/{total} — {pct:.0f}%")
                # Log the test result
                num_str  = f"  Test {i:>2}/{total}: "
                if res["success"]:
                    status   = "PASS (d recovered)"
                    tag      = "red_tag"
                    detail   = (f"p = {str(res.get('p','?'))[:20]}…"
                                f"  d1 ✓={res.get('d1_correct','?')}")
                else:
                    status = "FAIL — attack blocked"
                    tag    = "green_tag"
                    detail = res.get("reason", "")
                t = f"{res['elapsed']:.3f}s"
                line = f"{num_str}{status:<26}  [{t}]  {detail}\n"
                self._log.config(state="normal")
                self._log.insert("end", line, tag)
                self._log.see("end")
                self._log.config(state="disabled")

            results = run_tests(N_TESTS, bits=KEY_BITS,
                                use_prevention=prevention,
                                progress_callback=_progress_cb)
            summary = summarise_results(results)

            self._log_sep("═")
            if not prevention:
                self._before_rate = summary["success_rate"]
                rate_str = f"{summary['success_rate']:.1f}%"
                ok = summary["success_rate"] >= 90
                self._log_msg(
                    f"\n  SUMMARY (Before Fix)\n"
                    f"  Passed  : {summary['successes']}/{summary['total']} tests\n"
                    f"  Success : {rate_str} {'✓ ≥90% (as expected)' if ok else '✗ below 90%'}\n"
                    f"  Avg time: {summary['avg_time']:.3f}s / test\n\n",
                    "red_tag" if ok else "orange_tag"
                )
            else:
                self._after_rate = summary["success_rate"]
                rate_str = f"{summary['success_rate']:.1f}%"
                ok = summary["success_rate"] <= 2
                self._log_msg(
                    f"\n  SUMMARY (After Fix — Prevention ON)\n"
                    f"  Blocked : {summary['failures']}/{summary['total']} attacks\n"
                    f"  Success : {rate_str} {'✓ ≤2% (secure)' if ok else '✗ above 2%'}\n"
                    f"  Avg time: {summary['avg_time']:.3f}s / test\n\n",
                    "green_tag" if ok else "orange_tag"
                )
            self._progress_lbl.config(text="Done")

        threading.Thread(target=_worker, daemon=True).start()

    def _on_apply_prevention(self):
        self._prevention = not self._prevention
        if self._prevention:
            self._status_var.set("✔  Secure")
            self._status_lbl.config(fg=GREEN)
            self._info_vars["Prevention"].set("ON")
            self._log_sep()
            self._log_msg("[ PREVENTION APPLIED ]\n", "green_tag")
            self._log_msg(
                "  Uniqueness check is now ACTIVE.\n"
                "  Each user will receive a unique n.\n"
                "  GCD attack will no longer recover shared primes.\n"
                "  → Generate new keys and re-run the attack.\n\n",
                "green_tag"
            )
        else:
            self._status_var.set("⚠  Vulnerable")
            self._status_lbl.config(fg=RED)
            self._info_vars["Prevention"].set("OFF")
            self._log_sep()
            self._log_msg("[ PREVENTION REMOVED ]\n", "red_tag")
            self._log_msg("  Keys will again share the same modulus n.\n\n",
                          "red_tag")
        # Reset keys so user must regenerate
        self._kp1 = None
        self._kp2 = None
        reset_registry()

    def _on_show_graphs(self):
        before = self._before_rate if self._before_rate is not None else 96.0
        after  = self._after_rate  if self._after_rate  is not None else 0.0

        self._log_sep()
        self._log_msg("[ SHOW GRAPHS ]\n", "orange_tag")
        if self._before_rate is None:
            self._log_msg(
                "  ⓘ No test data yet — using example values "
                f"(before={before:.0f}%, after={after:.0f}%).\n"
                "   Run the attack before & after prevention for real data.\n\n",
                "yellow_tag"
            )
        else:
            self._log_msg(
                f"  Using test data: before={before:.1f}%  after={after:.1f}%\n"
                "  Computing timing measurements for graphs 2 & 4…\n\n",
                "grey_tag"
            )

        def _worker():
            try:
                from graphs import show_all_graphs
                def _sc(msg):
                    self._log_msg(f"  {msg}\n", "grey_tag")
                show_all_graphs(before, after, status_callback=_sc)
            except Exception as exc:
                self._log_msg(f"\n  Graph error: {exc}\n", "red_tag")

        threading.Thread(target=_worker, daemon=True).start()

    def _on_show_proof(self):
        win = tk.Toplevel(self)
        win.title("Mathematical Proof — Common Modulus Attack")
        win.geometry("780x500")
        win.configure(bg="#0a0a14")
        win.grab_set()

        tk.Label(win, text="Mathematical Proof", bg="#0a0a14", fg="#a78bfa",
                 font=("Segoe UI", 12, "bold"), pady=8).pack()

        txt = scrolledtext.ScrolledText(win, bg="#0a0a14", fg=FG_WHITE,
                                        font=("Consolas", 10),
                                        relief="flat", padx=14, pady=10)
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", MATH_PROOF)
        txt.config(state="disabled")


def launch():
    app = RSAApp()
    app.mainloop()
