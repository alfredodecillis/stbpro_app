# stbpro_dual_sync_ui_v3_watchdog_fixed.py
# - GUI invariata (4 grafici: ACC/GYR #1 e #2 a sinistra; 2 tabelle a destra)
# - Stato generale + stati per #1 e #2
# - Start sincronizzato SOLO dopo aver ricevuto il primo campione da entrambi
# - CSV: un dato ogni 0.5 s, timeline regolare (hold-last-value)
# - Connessione: ritentativi + watchdog no-data con ri-sottoscrizione/riconnessione
# - Batteria: derivata da mV (stabile) + EMA + slew-rate

import asyncio, struct, time, csv, os, threading, queue, sys
from collections import deque, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from bleak import BleakClient, BleakScanner
from bleak import BleakScanner

async def resolve_ble_device_windows(addr_hint: str | None, name_hint: str | None, scan_s: float = 8.0):
    """
    Restituisce (BLEDevice | None, elenco_trovati) su Windows.
    - Match ordine: MAC esatto -> MAC contiene/suffisso -> nome contiene name_hint (es. 'stb_pro').
    - elenco_trovati: lista di tuple (name, address, rssi) per log/debug.
    """
    if not sys.platform.startswith("win"):
        return None, []

    async with BleakScanner() as s:
        await asyncio.sleep(scan_s)
        pairs = list(s.discovered_devices_and_advertisement_data.values())

    found_list = []
    th = (addr_hint or "").lower().strip()
    nh = (name_hint or "").lower().strip()

    best = None
    for dev, adv in pairs:
        name = (dev.name or getattr(adv, "local_name", None) or "").strip()
        addr = (dev.address or "").strip()
        rssi = getattr(adv, "rssi", None)
        found_list.append((name, addr, rssi))

        a = addr.lower()
        n = name.lower()
        if th and a == th:
            best = dev; break
        if th and th in a:
            best = dev  # candidato (non uscire, magari troviamo esatto)
        if not best and nh and nh in n:
            best = dev

    return best, found_list
import sys, asyncio
if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass
        
# ===================== CONFIG =====================
ADDR_1 = "DA:F9:0A:9C:AD:07"  # STB_PRO #1
ADDR_2 = "E4:9D:3B:F9:E1:A0"  # STB_PRO #2

# UUID "combined" (ACC+GYR in un frame)
COMBINED_UUID_1 = "00c00000-0001-11e1-ac36-0002a5d5c51b"  # #1 noto
COMBINED_UUID_2 = "00e00000-0001-11e1-ac36-0002a5d5c51b"  # #2 noto

# BlueST
BLUEST_SERVICE   = "00000000-0001-11e1-9ab4-0002a5d5c51b"
BAT_UUID         = "00020000-0001-11e1-ac36-0002a5d5c51b"

# Candidati autodetect combined (fallback se la "nota" non manda dati)
COMBINED_CANDIDATES = [
    "00c00000-0001-11e1-ac36-0002a5d5c51b",
    "00e00000-0001-11e1-ac36-0002a5d5c51b",
    "00190000-0001-11e1-ac36-0002a5d5c51b",
    "00000100-0001-11e1-ac36-0002a5d5c51b",
    "00000014-0002-11e1-ac36-0002a5d5c51b",
]

CONNECT_TIMEOUT_S      = 10
CONNECT_RETRIES        = 5
RETRY_BACKOFF_BASE_S   = 1.2   # 1.2, 2.4, 3.6, ...
POST_CONNECT_WAIT_S    = 1.0

# GUI
TIMEWINDOW_MS          = 60_00  # 6 s visivi
REFRESH_MS             = 60

# CSV: 1 riga ogni 0.5 s
CSV_BIN_MS             = 500

# Avvio stream: attendi dati veri entro questo tempo, altrimenti cambia UUID/ri-sottoscrivi
START_DATA_TIMEOUT_S   = 2.5

# Watchdog durante streaming: se non arrivano dati per N secondi, resubscribe/reconnect
NO_DATA_WATCHDOG_S     = 5.0
MAX_NOTIFY_RESETS      = 2
MAX_MIDSTREAM_RECONNECTS = 1

# Batteria smoothing
BAT_UPDATE_MIN_DT      = 1.5    # s
BAT_EMA_ALPHA          = 0.08
BAT_MAX_STEP           = 1.0    # % max per update

# ===================== GUI deps =====================
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ===================== Utils =====================
def clamp(v, lo, hi): return max(lo, min(hi, v))

# Risoluzione device su Windows (per evitare “doppio aggancio” allo stesso)
async def resolve_ble_device_windows(target_hint: str, scan_s: float = 4.0):
    if sys.platform != "win32":
        return None
    async with BleakScanner() as scanner:
        await asyncio.sleep(scan_s)
        pairs = list(scanner.discovered_devices_and_advertisement_data.values())
    th = (target_hint or "").lower()
    for dev, adv in pairs:
        name = (dev.name or getattr(adv, "local_name", None) or "").lower()
        addr = (dev.address or "").lower()
        if th and th == addr:
            return dev
    # fallback: match parziale/suffisso
    for dev, adv in pairs:
        name = (dev.name or getattr(adv, "local_name", None) or "").lower()
        addr = (dev.address or "").lower()
        if (th and th in addr) or ("stb_pro" in name and (not th or th in name or th in addr)):
            return dev
    return None

# Combined frame: 2B ts + 6*int16 (acc mg, gyr 0.1 dps)
def parse_combined(payload: bytes):
    if len(payload) < 14: return None
    ts = int.from_bytes(payload[0:2], "little", signed=False)
    ax, ay, az, gx, gy, gz = struct.unpack_from("<hhhhhh", payload, 2)
    return ts, ax, ay, az, gx/10.0, gy/10.0, gz/10.0

# Batteria: stabilizziamo leggendo SOLO la tensione mV (2B in range plausibile) e mappando 3.30→0%, 4.20→100%
def parse_battery(payload: bytes):
    b = bytes(payload); mv=None
    for i in range(len(b)-1):
        v = int.from_bytes(b[i:i+2], "little", signed=False)
        if 3200 <= v <= 4400:
            mv = float(v)
            break
    if mv is None:
        return None, None
    # Map 3.30 V -> 0%, 4.20 V -> 100%
    pct = (mv - 3300.0) * (100.0 / 900.0)
    pct = clamp(pct, 0.0, 100.0)
    return pct, mv

class SlewEMA:
    def __init__(self, alpha=BAT_EMA_ALPHA, max_step=BAT_MAX_STEP):
        self.alpha = alpha; self.max_step = max_step
        self.ema = None; self.last = None; self.last_ui_t = 0.0
    def update(self, x, now):
        if x is None: return self.last
        self.ema = x if self.ema is None else (self.ema + self.alpha*(x - self.ema))
        cand = self.ema if self.last is None else self.last + clamp(self.ema - self.last, -self.max_step, self.max_step)
        self.last = cand; self.last_ui_t = now
        return self.last

# ===================== BLE Worker =====================
@dataclass
class DevCfg:
    id: int
    addr: str
    combined_uuid: str | None  # preferita

class BLEWorker(threading.Thread):
    def __init__(self, cfg: DevCfg, ui_queue, stop_event, start_barrier, status_cb):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.uiq = ui_queue
        self.stop_event = stop_event
        self.barrier = start_barrier
        self.status_cb = status_cb
        self.client: BleakClient | None = None
        self.preferred_uuid = cfg.combined_uuid
        self.active_uuid = None

        # watchdog
        self.last_data_t = 0.0
        self.notify_resets = 0
        self.midstream_reconnects = 0
        self.started_once = False

    def log(self, msg): self.status_cb(self.cfg.id, msg)

    async def _connect_with_retries(self):
    last_exc = None
    for attempt in range(1, CONNECT_RETRIES + 1):
        self.log(f"Connessione a {self.cfg.addr} (tentativo {attempt}/{CONNECT_RETRIES}, timeout {CONNECT_TIMEOUT_S}s)…")

        client_arg = self.cfg.addr  # default: uso la stringa address
        # Su Windows prova sempre a risolvere via scan e usa il BLEDevice risultante
        if sys.platform.startswith("win"):
            dev, seen = await resolve_ble_device_windows(
                addr_hint=(self.cfg.addr or ""),
                name_hint="stb_pro",
                scan_s=8.0
            )
            if seen:
                self.log("Scan visti:\n" + "\n".join(
                    [f"  - name='{n or '-'}' addr={a or '-'} rssi={r}" for (n,a,r) in seen]
                ))
            if dev is None:
                self.log("Nessun match allo scan. Verifica: Posizione ON, device non accoppiato, riavvio BT/PC.")
            else:
                client_arg = dev

        cl = BleakClient(client_arg, disconnected_callback=lambda c: self.log("Disconnesso."))
        try:
            await asyncio.wait_for(cl.connect(), timeout=CONNECT_TIMEOUT_S)
            await asyncio.sleep(POST_CONNECT_WAIT_S)
            try:
                await asyncio.wait_for(cl.get_services(), timeout=6)
            except Exception:
                pass

            # (opzionale) verifica servizio BlueST e suggerisci clear della GATT cache se manca
            try:
                svcs = await cl.get_services()
                if not any(s.uuid.lower() == BLUEST_SERVICE for s in svcs):
                    self.log("⚠️ Servizio BlueST non trovato. Probabile GATT cache: rimuovi i device in Windows, riavvia BT o PC e riprova.")
                else:
                    self.log("Servizio BlueST presente.")
            except Exception:
                pass

            self.client = cl
            self.log("Connesso.")
            return
        except Exception as e:
            last_exc = e
            self.log(f"Errore: {type(e).__name__}: {e}")
            try: await cl.disconnect()
            except Exception: pass
            if attempt < CONNECT_RETRIES:
                backoff = RETRY_BACKOFF_BASE_S * attempt
                self.log(f"Riprovo tra {backoff:.1f}s…")
                await asyncio.sleep(backoff)

    raise last_exc if last_exc else RuntimeError("Connessione fallita")

    def _on_bat(self, _h, data: bytearray):
        pct, mv = parse_battery(data)
        self.uiq.put(("bat", self.cfg.id, pct, mv, time.time()))

    def _on_combined(self, _h, data: bytearray):
        p = parse_combined(data)
        if not p: return
        ts, ax, ay, az, gx, gy, gz = p
        now = time.time()
        self.last_data_t = now
        if not self.started_once:
            self.started_once = True
            self.uiq.put(("ready", self.cfg.id))
            self.log(f"Dati ricevuti su {self.active_uuid}")
        self.uiq.put(("accgyr", self.cfg.id, now, ts, ax, ay, az, gx, gy, gz))

    async def _start_bat_notify(self):
        try:
            await asyncio.wait_for(self.client.start_notify(BAT_UUID, self._on_bat), timeout=4)
            self.log("notify BAT ON")
        except Exception as e:
            self.log(f"(BAT notify fallita: {e})")

    async def _try_start_combined(self, uuid):
        self.log(f"Tento combined su {uuid}…")
        self.active_uuid = uuid
        self.last_data_t = 0.0
        got_first = asyncio.Event()
        def _tmp(h, data):
            self._on_combined(h, data)
            if not got_first.is_set(): got_first.set()
        try:
            await asyncio.wait_for(self.client.start_notify(uuid, _tmp), timeout=4)
        except Exception as e:
            self.log(f"(start_notify fallita su {uuid}: {e})")
            return False
        try:
            await asyncio.wait_for(got_first.wait(), timeout=START_DATA_TIMEOUT_S)
            return True
        except asyncio.TimeoutError:
            self.log(f"Nessun dato entro {START_DATA_TIMEOUT_S}s su {uuid}.")
            try: await self.client.stop_notify(uuid)
            except Exception: pass
            return False

    async def _start_combined_with_fallbacks(self):
        tried = []
        if self.preferred_uuid:
            ok = await self._try_start_combined(self.preferred_uuid)
            tried.append(self.preferred_uuid)
            if ok: return True
        for cu in COMBINED_CANDIDATES:
            if cu in tried: continue
            ok = await self._try_start_combined(cu)
            if ok:
                self.preferred_uuid = cu
                return True
        return False

    async def _ensure_streaming(self):
        now = time.time()
        silent_for = (now - self.last_data_t) if self.last_data_t > 0 else NO_DATA_WATCHDOG_S + 1
        if silent_for <= NO_DATA_WATCHDOG_S:
            return True
        # resubscribe
        if self.notify_resets < MAX_NOTIFY_RESETS:
            self.notify_resets += 1
            self.log(f"Watchdog: nessun dato da {silent_for:.1f}s → riattivo notify ({self.notify_resets}/{MAX_NOTIFY_RESETS})…")
            try:
                if self.active_uuid:
                    try: await self.client.stop_notify(self.active_uuid)
                    except Exception: pass
                ok = await self._start_combined_with_fallbacks()
                if ok:
                    self.log("Notify riattivata con successo.")
                    return True
            except Exception as e:
                self.log(f"(resubscribe fallita: {e})")
        # reconnect
        if self.midstream_reconnects < MAX_MIDSTREAM_RECONNECTS:
            self.midstream_reconnects += 1
            self.log("Watchdog: riconnessione a caldo…")
            try:
                try: await self.client.disconnect()
                except Exception: pass
                await self._connect_with_retries()
                await self._start_bat_notify()
                ok = await self._start_combined_with_fallbacks()
                if ok:
                    self.notify_resets = 0
                    self.log("Riconnesso e notify attiva.")
                    return True
            except Exception as e:
                self.log(f"(riconnessione fallita: {e})")
        self.log("⚠️ Stream non recuperabile. Chiudo.")
        return False

    async def run_async(self):
        try:
            await self._connect_with_retries()
        except Exception as e:
            self.log(f"Errore connessione: {e}")
            return

        try:
            self.log("In attesa dell’altro device…")
            self.barrier.wait(timeout=15)
        except Exception:
            self.log("⚠️ Barriera non raggiunta: avvio comunque.")

        await self._start_bat_notify()
        ok = await self._start_combined_with_fallbacks()
        if not ok:
            self.log("⚠️ Nessuna stream accesa (combined). Chiudo.")
            return

        while not self.stop_event.is_set():
            ok = await self._ensure_streaming()
            if not ok:
                break
            await asyncio.sleep(0.2)

        try:
            if self.client:
                try:
                    if self.active_uuid:
                        await self.client.stop_notify(self.active_uuid)
                except Exception: pass
                try: await self.client.stop_notify(BAT_UUID)
                except Exception: pass
                try: await self.client.disconnect()
                except Exception: pass
        except Exception:
            pass
        self.log("Chiuso.")

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.run_async())
        finally:
            try: loop.stop()
            finally: loop.close()

# ===================== APP =====================
class App:
    def __init__(self, root):
        self.root = root
        root.title("STB_PRO dual — ACC/GYR live")

        self.uiq = queue.Queue()
        self.stop_event = threading.Event()
        self.workers = []
        self.barrier = None
        self.ready = set()
        self.closing = False

        # timeline globale continua
        self.t0 = None
        self.t_last_global = 0

        # CSV bins da 0.5 s per device
        self.csv_bins = {1: {}, 2: {}}

        # filtri batteria
        self.bat_filters = {1: SlewEMA(), 2: SlewEMA()}

        # CSV path
        self.csv_path = None

        # ===== Top bar =====
        top = ttk.Frame(root, padding=6); top.pack(fill="x")
        self.btn_conn = ttk.Button(top, text="Connetti", command=self.on_connect)
        self.btn_stop = ttk.Button(top, text="Stop", command=self.on_stop, state="disabled")
        self.btn_conn.pack(side="left", padx=(0,6)); self.btn_stop.pack(side="left")

        self.lbl_gen = ttk.Label(top, text="Stato generale: Pronto"); self.lbl_gen.pack(side="left", padx=14)
        self.lbl_s1  = ttk.Label(top, text="Stato #1: —"); self.lbl_s1.pack(side="left", padx=10)
        self.lbl_b1  = ttk.Label(top, text="Batteria #1: —"); self.lbl_b1.pack(side="left", padx=6)
        self.lbl_s2  = ttk.Label(top, text="Stato #2: —"); self.lbl_s2.pack(side="left", padx=10)
        self.lbl_b2  = ttk.Label(top, text="Batteria #2: —"); self.lbl_b2.pack(side="left", padx=6)

        # ===== Corpo: sinistra grafici, destra tabelle =====
        body = ttk.Frame(root, padding=6); body.pack(fill="both", expand=True)

        self.fig = Figure(figsize=(9.0, 6.8), dpi=100)
        self.ax11 = self.fig.add_subplot(221); self._setup_ax(self.ax11, "ACC #1", "mg")
        self.ax21 = self.fig.add_subplot(223); self._setup_ax(self.ax21, "GYR #1", "deg/s", xlabel=True)
        self.ax12 = self.fig.add_subplot(222); self._setup_ax(self.ax12, "ACC #2", "mg")
        self.ax22 = self.fig.add_subplot(224); self._setup_ax(self.ax22, "GYR #2", "deg/s", xlabel=True)
        self.fig.subplots_adjust(hspace=0.35, wspace=0.25, top=0.96, bottom=0.08, left=0.07, right=0.99)

        self.canvas = FigureCanvasTkAgg(self.fig, master=body)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(side="left", fill="both", expand=True)

        right = ttk.Frame(body); right.pack(side="left", fill="both", expand=False, padx=(6,0))
        self.tree1 = self._make_table(right, "ACC/GYR #1 — ultimi 50")
        self.tree2 = self._make_table(right, "ACC/GYR #2 — ultimi 50")

        # buffer plotting per device
        self.buff = {
            1: {k: deque(maxlen=TIMEWINDOW_MS) for k in ["t","ax","ay","az","gx","gy","gz"]},
            2: {k: deque(maxlen=TIMEWINDOW_MS) for k in ["t","ax","ay","az","gx","gy","gz"]},
        }
        # linee
        self.lines = {}
        for dev_id, ax_acc, ax_gyr in [(1,self.ax11,self.ax21),(2,self.ax12,self.ax22)]:
            (lax,) = ax_acc.plot([], [], label="ax")
            (lay,) = ax_acc.plot([], [], label="ay")
            (laz,) = ax_acc.plot([], [], label="az"); ax_acc.legend(loc="upper left")
            (lgx,) = ax_gyr.plot([], [], label="gx")
            (lgy,) = ax_gyr.plot([], [], label="gy")
            (lgz,) = ax_gyr.plot([], [], label="gz"); ax_gyr.legend(loc="upper left")
            self.lines[dev_id] = {"ax":lax,"ay":lay,"az":laz,"gx":lgx,"gy":lgy,"gz":lgz}

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._after = root.after(REFRESH_MS, self.refresh)

    # ====== UI helpers ======
    def _setup_ax(self, ax, title, ylab, xlabel=False):
        ax.set_title(title); ax.set_ylabel(ylab)
        ax.set_xlabel("tempo [s]" if xlabel else "")
        ax.grid(True)

    def _make_table(self, parent, title):
        frm = ttk.LabelFrame(parent, text=title, padding=4); frm.pack(fill="both", expand=True, pady=4)
        cols=("t[s]","ax","ay","az","gx","gy","gz")
        tree = ttk.Treeview(frm, columns=cols, show="headings", height=18)
        for c in cols:
            w = 80 if c=="t[s]" else 70
            tree.heading(c, text=c); tree.column(c, width=w, anchor="e")
        vsb = ttk.Scrollbar(frm, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.grid(row=0, column=0, sticky="nsew"); vsb.grid(row=0, column=1, sticky="ns")
        frm.grid_columnconfigure(0, weight=1); frm.grid_rowconfigure(0, weight=1)
        return tree

    def _set_state(self, dev_id, msg):
        if dev_id == 1: self.lbl_s1.config(text=f"Stato #1: {msg}")
        else:           self.lbl_s2.config(text=f"Stato #2: {msg}")

    def _set_bat(self, dev_id, pct, mv):
        if pct is None and mv is None:
            txt = "—"
        else:
            txt = f"{int(round(pct))}%" if pct is not None else "—"
            if mv is not None: txt += f" ({mv/1000:.2f} V)"
        (self.lbl_b1 if dev_id==1 else self.lbl_b2).config(text=f"Batteria #{dev_id}: {txt}")

    def _set_general(self, txt): self.lbl_gen.config(text=f"Stato generale: {txt}")

    def _global_last_time(self):
        last = 0.0
        for dev in (1,2):
            t = self.buff[dev]["t"]
            if t: last = max(last, t[-1])
        return last

    # ====== Pulsanti ======
    def on_connect(self):
        if self.closing: return
        self._set_general("Connessione…")
        self.btn_conn.configure(state="disabled"); self.btn_stop.configure(state="disabled")
        self._set_state(1, "Connessione…"); self._set_state(2, "Connessione…")
        self._set_bat(1, None, None); self._set_bat(2, None, None)
        self.ready.clear(); self.stop_event.clear()
        # reset CSV bins
        self.csv_bins = {1: {}, 2: {}}
        self.bat_filters = {1: SlewEMA(), 2: SlewEMA()}
        self.csv_path = (Path.home()/ "Desktop" / f"stbpro_dual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")

        # timeline continua
        self.t_last_global = self._global_last_time()
        epsilon = 0.02
        self.t0 = time.time() - (self.t_last_global + epsilon)

        self.barrier = threading.Barrier(2)
        w1 = BLEWorker(DevCfg(1, ADDR_1, COMBINED_UUID_1), self.uiq, self.stop_event, self.barrier, self._set_state)
        w2 = BLEWorker(DevCfg(2, ADDR_2, COMBINED_UUID_2), self.uiq, self.stop_event, self.barrier, self._set_state)
        self.workers = [w1, w2]
        for w in self.workers: w.start()

    def on_stop(self):
        if self.closing: return
        try: self.root.after_cancel(self._after)
        except Exception: pass
        self.stop_event.set()
        for w in self.workers:
            try: w.join(timeout=2.0)
            except Exception: pass
        try: self._save_merged_csv_0p5s()
        except Exception as e: print("(CSV fallito)", e)
        self._set_state(1, "Disconnesso."); self._set_state(2, "Disconnesso.")
        self._set_general("Arrestato")
        self.btn_conn.configure(state="normal"); self.btn_stop.configure(state="disabled")
        self._after = self.root.after(REFRESH_MS, self.refresh)

    def on_close(self):
        if self.closing: return
        self.closing = True
        try: self.root.after_cancel(self._after)
        except Exception: pass
        self._set_general("Chiusura…")
        self.stop_event.set()
        for w in self.workers:
            try: w.join(timeout=2.0)
            except Exception: pass
        try: self._save_merged_csv_0p5s()
        except Exception: pass
        try: self.root.destroy()
        except Exception: pass

    # ====== Main refresh ======
    def refresh(self):
        try:
            while True:
                item = self.uiq.get_nowait()
                kind = item[0]
                if kind == "ready":
                    self.ready.add(item[1])
                    if len(self.ready) == 2:
                        self.btn_stop.configure(state="normal")
                        self._set_general("Streaming")
                elif kind == "bat":
                    _, dev_id, pct, mv, tnow = item
                    if pct is not None: pct = clamp(pct, 0.0, 100.0)
                    filt = self.bat_filters[dev_id]
                    if tnow - filt.last_ui_t >= BAT_UPDATE_MIN_DT or filt.last_ui_t == 0.0:
                        spct = filt.update(pct, tnow)
                        self._set_bat(dev_id, spct, mv)
                elif kind == "accgyr":
                    _, dev_id, t_host, ts_ble, ax, ay, az, gx, gy, gz = item
                    if self.t0 is None:
                        self.t0 = time.time() - (self._global_last_time() + 0.02)
                    t_s = max(0.0, t_host - self.t0)
                    B = self.buff[dev_id]
                    B["t"].append(t_s)
                    B["ax"].append(ax); B["ay"].append(ay); B["az"].append(az)
                    B["gx"].append(gx); B["gy"].append(gy); B["gz"].append(gz)
                    tree = self.tree1 if dev_id==1 else self.tree2
                    tree.insert("", "end", values=(f"{t_s:7.2f}", ax, ay, az, f"{gx:.1f}", f"{gy:.1f}", f"{gz:.1f}"))
                    ch = tree.get_children()
                    if len(ch) > 50: tree.delete(ch[0])
                    # CSV a 0.5 s: ultimo del bin
                    t_ms = int(round(t_s*1000))
                    bin_ms = (t_ms // CSV_BIN_MS) * CSV_BIN_MS
                    self.csv_bins[dev_id][bin_ms] = [ax, ay, az, gx, gy, gz]
        except queue.Empty:
            pass

        # aggiorna grafici
        for dev_id, ax_acc, ax_gyr in [(1,self.ax11,self.ax21),(2,self.ax12,self.ax22)]:
            B = self.buff[dev_id]; t=list(B["t"])
            if not t: continue
            tmax = t[-1]; tmin = max(0.0, tmax - TIMEWINDOW_MS/1000.0)
            i0 = 0
            for k in range(len(t)-1, -1, -1):
                if t[k] < tmin: i0 = k+1; break
            tf = t[i0:]
            # ACC
            ax = list(B["ax"])[i0:]; ay = list(B["ay"])[i0:]; az = list(B["az"])[i0:]
            L = self.lines[dev_id]
            L["ax"].set_data(tf, ax); L["ay"].set_data(tf, ay); L["az"].set_data(tf, az)
            if tf:
                ax_acc.set_xlim(max(0, tf[0]), max(tf[-1], 3))
                ymin = min(ax+ay+az); ymax = max(ax+ay+az); pad = max(50.0, 0.1*(ymax-ymin+1))
                ax_acc.set_ylim(ymin-pad, ymax+pad)
            # GYR
            gx = list(B["gx"])[i0:]; gy = list(B["gy"])[i0:]; gz = list(B["gz"])[i0:]
            L["gx"].set_data(tf, gx); L["gy"].set_data(tf, gy); L["gz"].set_data(tf, gz)
            if tf:
                ax_gyr.set_xlim(max(0, tf[0]), max(tf[-1], 3))
                ymin = min(gx+gy+gz); ymax = max(gx+gy+gz); pad = max(5.0, 0.1*(ymax-ymin+1))
                ax_gyr.set_ylim(ymin-pad, ymax+pad)

        self.canvas.draw_idle()
        if not self.closing:
            self._after = self.root.after(REFRESH_MS, self.refresh)

    # ====== CSV (0.5 s, timeline regolare) ======
    def _save_merged_csv_0p5s(self):
        b1 = self.csv_bins[1]; b2 = self.csv_bins[2]
        if not b1 and not b2:
            print("→ Nessun dato, CSV non creato."); return

        max_bin = 0
        if b1: max_bin = max(max_bin, max(b1.keys()))
        if b2: max_bin = max(max_bin, max(b2.keys()))

        last1 = [None]*6
        last2 = [None]*6

        if self.csv_path is None:
            self.csv_path = Path.home() / "Desktop" / f"stbpro_dual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(self.csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["t_s",
                        "ax#1","ay#1","az#1","gx#1","gy#1","gz#1",
                        "ax#2","ay#2","az#2","gx#2","gy#2","gz#2"])
            b = 0
            while b <= max_bin:
                if b in b1: last1 = b1[b][:]
                if b in b2: last2 = b2[b][:]
                row = [f"{b/1000.0:.3f}"] + \
                      [("" if v is None else v) for v in last1] + \
                      [("" if v is None else v) for v in last2]
                w.writerow(row)
                b += CSV_BIN_MS

        print("→ CSV salvato:", os.path.abspath(self.csv_path))

# ===================== MAIN =====================
def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names(): style.theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
