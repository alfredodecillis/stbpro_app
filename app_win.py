# stbpro_dual_sync_ui_v9_pairfix.py
# - Pre-pairing SEQUENZIALE (uno alla volta) prima di aprire gli stream
# - NIENTE unpair automatico allo stop (solo fallback su errore)
# - Pair "on-demand" se start_notify fallisce per permessi (Access denied)
# - UI invariata; CSV 0.5 s invariato; finestra grafici 6 s; throttling/decimazione come v8

import sys, asyncio, contextlib, struct, time, csv, os, threading, queue
from collections import deque, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from bleak import BleakScanner, BleakClient

# ---- Event loop policy (Windows) ----
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

# ===================== CONFIG =====================
ADDR_1 = "DA:F9:0A:9C:AD:07"   # STB_PRO #1
ADDR_2 = "E4:9D:3B:F9:E1:A0"   # STB_PRO #2

# UUID "combined" (ACC+GYR in un frame) note/attese
COMBINED_UUID_1 = "00c00000-0001-11e1-ac36-0002a5d5c51b"
COMBINED_UUID_2 = "00e00000-0001-11e1-ac36-0002a5d5c51b"

# BlueST
BLUEST_SERVICE = "00000000-0001-11e1-9ab4-0002a5d5c51b"
BAT_UUID       = "00020000-0001-11e1-ac36-0002a5d5c51b"

# Candidati (nel dubbio)
COMBINED_CANDIDATES = [
    "00c00000-0001-11e1-ac36-0002a5d5c51b",
    "00e00000-0001-11e1-ac36-0002a5d5c51b",
    "00190000-0001-11e1-ac36-0002a5d5c51b",
    "00000100-0001-11e1-ac36-0002a5d5c51b",
    "00000014-0002-11e1-ac36-0002a5d5c51b",
]

# Connessione/risoluzione
CONNECT_TIMEOUT_S        = 10
POST_CONNECT_WAIT_S      = 1.0
BARRIER_TIMEOUT_S        = 8.0
SCAN_SLICE_S             = 2.5
RESOLVE_OVERALL_TIMEOUT  = 35.0
RESOLVE_BACKOFF_S        = 2.0
RETRY_BACKOFF_S          = 3.0

# Watchdog & notify
START_DATA_TIMEOUT_S     = 2.5
NO_DATA_WATCHDOG_S       = 5.0
MAX_NOTIFY_RESETS        = 2
MAX_MIDSTREAM_RECONNECTS = 1

# Disconnessione “pulita”
UNPAIR_ON_DISCONNECT     = False   # ← disabilitato per evitare loop di pairing
COOLDOWN_AFTER_STOP_S    = 1.2

# === GUI timing ===
TIMEWINDOW_MS            = 60_00
REFRESH_TICK_MS          = 30

# Throttling/decimazione (anti-lag)
PLOT_INTERVAL_S          = 0.08
TABLE_INTERVAL_S         = 0.20
YLIM_INTERVAL_S          = 0.50
MAX_QUEUE_DRAIN_PER_TICK = 600
MAX_POINTS_PER_LINE      = 900

# CSV
CSV_BIN_MS               = 500

# Batteria smoothing
BAT_UPDATE_MIN_DT        = 1.5
BAT_EMA_ALPHA            = 0.08
BAT_MAX_STEP             = 1.0

# ===================== GUI deps =====================
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ===================== Utils & parsing =====================
def clamp(v, lo, hi): return max(lo, min(hi, v))
def norm_mac(s: str) -> str: return (s or "").lower()
def mac_suffix(s: str, n=6) -> str:
    s = norm_mac(s).replace(":", "")
    return s[-n:]

def parse_combined(payload: bytes):
    if len(payload) < 14: return None
    ts = int.from_bytes(payload[0:2], "little", signed=False)
    ax, ay, az, gx, gy, gz = struct.unpack_from("<hhhhhh", payload, 2)
    return ts, ax, ay, az, gx/10.0, gy/10.0, gz/10.0

def parse_battery(payload: bytes):
    b = bytes(payload); pct=None; mv=None
    for i in range(len(b)):
        if 0 <= b[i] <= 100:
            pct = float(b[i]); break
    for i in range(len(b)-1):
        v = int.from_bytes(b[i:i+2], "little", signed=False)
        if 3000 <= v <= 4400: mv = float(v); break
    if pct is None and mv is not None:
        pct = clamp((mv - 3300.0) * (100.0/900.0), 0.0, 100.0)
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

# ===================== Resolver =====================
def _is_connectable(adv) -> bool:
    try:
        return bool(getattr(adv, "is_connectable", True))
    except Exception:
        return True

@dataclass
class Resolved:
    id: int
    want_mac: str
    device: object
    name: str
    rssi: int

class Resolver(threading.Thread):
    def __init__(self, addr1: str, addr2: str, uiq: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.addr1 = norm_mac(addr1); self.addr2 = norm_mac(addr2)
        self.uiq = uiq; self.stop_event = stop_event

    async def _scan_slice(self, secs: float):
        async with BleakScanner() as s:
            await asyncio.sleep(secs)
            pairs = list(s.discovered_devices_and_advertisement_data.values())
        try:
            pairs.sort(key=lambda p: getattr(p[1], "rssi", -9999), reverse=True)
        except Exception:
            pass
        return pairs

    async def _resolve_both(self):
        t0 = time.time()
        suf1 = mac_suffix(self.addr1); suf2 = mac_suffix(self.addr2)
        f1 = None; f2 = None
        while not self.stop_event.is_set():
            if time.time() - t0 > RESOLVE_OVERALL_TIMEOUT:
                return None, "Timeout risoluzione"
            pairs = await self._scan_slice(SCAN_SLICE_S)
            # cand "STB_PRO" e connectable
            cand = []
            for dev, adv in pairs:
                name = (dev.name or getattr(adv, "local_name", None) or "")
                addr = norm_mac(dev.address)
                if "stb_pro" not in name.lower(): continue
                if not _is_connectable(adv): continue
                rssi = getattr(adv, "rssi", -9999)
                cand.append((dev, adv, name, addr, rssi))
            # match
            for dev, adv, name, addr, rssi in cand:
                s = mac_suffix(addr)
                if f1 is None and (addr == self.addr1 or s == suf1):
                    f1 = Resolved(1, self.addr1, dev, name, rssi)
                elif f2 is None and (addr == self.addr2 or s == suf2):
                    f2 = Resolved(2, self.addr2, dev, name, rssi)
            # fallback: due migliori distinti
            if (f1 is None or f2 is None) and len(cand) >= 2:
                seen = {}; ordered = []
                for dev, adv, name, addr, rssi in cand:
                    if addr in seen: continue
                    seen[addr] = True; ordered.append((dev, name, addr, rssi))
                ordered.sort(key=lambda x: x[3], reverse=True)
                if len(ordered) >= 2:
                    d1, n1, a1, r1 = ordered[0]
                    d2, n2, a2, r2 = ordered[1]
                    if f1 is None: f1 = Resolved(1, self.addr1, d1, n1, r1)
                    if f2 is None: f2 = Resolved(2, self.addr2, d2, n2, r2)
            if f1 and f2:
                return (f1, f2), None
            await asyncio.sleep(RESOLVE_BACKOFF_S)

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result, err = loop.run_until_complete(self._resolve_both())
            if result:
                r1, r2 = result
                self.uiq.put(("resolved_both", r1, r2))
            else:
                self.uiq.put(("resolve_error", err or "Errore sconosciuto"))
        finally:
            with contextlib.suppress(Exception): loop.stop()
            with contextlib.suppress(Exception): loop.close()

# ============== PRE-PAIRING SEQUENZIALE (UNO ALLA VOLTA) ==============
PAIR_MUTEX = threading.Lock()

class PrePairer(threading.Thread):
    """Accoppia #1 e #2 in sequenza (se non già paired), poi segnala 'prepair_done'."""
    def __init__(self, r1: Resolved, r2: Resolved, uiq: queue.Queue, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.r1 = r1; self.r2 = r2
        self.uiq = uiq; self.stop_event = stop_event

    async def _connect_deadline(self, client: BleakClient, timeout=CONNECT_TIMEOUT_S):
        task = asyncio.create_task(client.connect())
        done, _ = await asyncio.wait({task}, timeout=timeout)
        if not done:
            with contextlib.suppress(Exception): await client.disconnect()
            with contextlib.suppress(Exception): task.cancel(); await task
            raise asyncio.TimeoutError("Connect deadline exceeded")
        await task
        await asyncio.sleep(POST_CONNECT_WAIT_S)

    async def _pair_one(self, dev_id: int, device_obj):
        disp = f"{getattr(device_obj, 'address', 'n/a')} ({getattr(device_obj, 'name', '—')})"
        self.uiq.put(("pair_status", dev_id, f"Accoppiamento {disp}…"))
        client = BleakClient(device_obj)
        try:
            await self._connect_deadline(client)
        except Exception as e:
            self.uiq.put(("pair_status", dev_id, f"Connessione per pair fallita: {e}"))
            return
        # Verifica/parifica
        try:
            paired = True
            try: paired = await client.is_paired()
            except Exception: paired = True  # alcuni backend non espongono
            if not paired and sys.platform == "win32":
                with PAIR_MUTEX:  # SERIALIZZA il pairing
                    try:
                        ok = await client.pair(protection_level=1)
                        self.uiq.put(("pair_status", dev_id, f"Pair esito: {ok}"))
                    except Exception as e:
                        self.uiq.put(("pair_status", dev_id, f"Pair fallito: {e}"))
            else:
                self.uiq.put(("pair_status", dev_id, "Già paired"))
        finally:
            with contextlib.suppress(Exception): await client.disconnect()
            self.uiq.put(("pair_status", dev_id, "Pairing OK"))

    async def run_async(self):
        # #1 poi #2 (se stop richiesto, esce)
        if not self.stop_event.is_set():
            await self._pair_one(1, self.r1.device)
        if not self.stop_event.is_set():
            await self._pair_one(2, self.r2.device)
        self.uiq.put(("prepair_done", self.r1, self.r2))

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.run_async())
        finally:
            with contextlib.suppress(Exception): loop.stop()
            with contextlib.suppress(Exception): loop.close()

# ===================== Worker BLE =====================
@dataclass
class DevCfg:
    id: int
    device: object
    preferred_uuid: str | None

class BLEWorker(threading.Thread):
    def __init__(self, cfg: DevCfg, uiq: queue.Queue, stop_event: threading.Event,
                 start_barrier: threading.Barrier, status_cb, generation: int):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.uiq = uiq
        self.stop_event = stop_event
        self.barrier = start_barrier
        self.status_cb = status_cb
        self.client: BleakClient | None = None
        self.preferred_uuid = cfg.preferred_uuid
        self.active_uuid = None
        self.last_data_t = 0.0
        self.notify_resets = 0
        self.midstream_reconnects = 0
        self.started_once = False
        self.generation = generation

    def log(self, msg): self.status_cb(self.cfg.id, msg)

    async def _connect_once(self):
        target = self.cfg.device
        disp = f"{getattr(target, 'address', 'n/a')} ({getattr(target, 'name', '—')})"
        self.log(f"Connessione a {disp} (timeout {CONNECT_TIMEOUT_S}s)…")
        cl = BleakClient(target, disconnected_callback=lambda c: self.log("Disconnesso."))
        task = asyncio.create_task(cl.connect())
        done, _ = await asyncio.wait({task}, timeout=CONNECT_TIMEOUT_S)
        if not done:
            with contextlib.suppress(Exception): await cl.disconnect()
            with contextlib.suppress(Exception): task.cancel(); await task
            raise asyncio.TimeoutError("Connect deadline exceeded")
        await task
        await asyncio.sleep(POST_CONNECT_WAIT_S)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(cl.get_services(), timeout=5)
        self.client = cl
        self.uiq.put(("connected", self.cfg.id, self.generation))
        self.log("Connesso.")

    async def _hard_close(self, do_unpair=False):
        if not self.client: return
        try:
            if self.active_uuid:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(self.client.stop_notify(self.active_uuid), timeout=2)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.client.stop_notify(BAT_UUID), timeout=2)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.client.disconnect(), timeout=4)
            if do_unpair and sys.platform == "win32":
                with contextlib.suppress(Exception):
                    ok = await asyncio.wait_for(self.client.unpair(), timeout=3)
                    self.log(f"Unpair esito: {ok}")
        except Exception as e:
            self.log(f"(hard_close note: {e})")

    async def _start_bat_notify(self):
        try:
            await asyncio.wait_for(self.client.start_notify(BAT_UUID, self._on_bat), timeout=4)
            self.log("notify BAT ON")
        except Exception as e:
            self.log(f"(BAT notify fallita: {e})")

    def _on_bat(self, _h, data: bytearray):
        if self.stop_event.is_set(): return
        pct, mv = parse_battery(data)
        self.uiq.put(("bat", self.cfg.id, pct, mv, time.time(), self.generation))

    def _on_combined(self, _h, data: bytearray):
        if self.stop_event.is_set(): return
        p = parse_combined(data)
        if not p: return
        ts, ax, ay, az, gx, gy, gz = p
        now = time.time()
        self.last_data_t = now
        if not self.started_once:
            self.started_once = True
            self.uiq.put(("ready", self.cfg.id, self.generation))
            self.log(f"Dati ricevuti su {self.active_uuid}")
        self.uiq.put(("accgyr", self.cfg.id, now, ts, ax, ay, az, gx, gy, gz, self.generation))

    def _is_access_denied(self, exc: Exception) -> bool:
        s = str(exc).lower()
        return ("access is denied" in s) or ("0x80070005" in s)

    async def _try_start_combined(self, uuid):
        self.active_uuid = uuid
        got_first = asyncio.Event()
        def _tmp(h, data):
            self._on_combined(h, data)
            if not got_first.is_set(): got_first.set()
        try:
            await asyncio.wait_for(self.client.start_notify(uuid, _tmp), timeout=4)
        except Exception as e:
            self.log(f"(start_notify fallita su {uuid}: {e})")
            # se errori di permesso → prova pairing on-demand
            if sys.platform == "win32" and self._is_access_denied(e):
                self.log("Access denied → provo pairing on-demand…")
                try:
                    with PAIR_MUTEX:
                        ok = await self.client.pair(protection_level=1)
                        self.log(f"Pair on-demand: {ok}")
                    # riprova
                    await asyncio.wait_for(self.client.start_notify(uuid, _tmp), timeout=4)
                except Exception as e2:
                    self.log(f"(on-demand pair/start fallito: {e2})")
                    return False
            else:
                return False
        # attesa primo dato
        try:
            await asyncio.wait_for(got_first.wait(), timeout=START_DATA_TIMEOUT_S)
            return True
        except asyncio.TimeoutError:
            self.log(f"Nessun dato entro {START_DATA_TIMEOUT_S}s su {uuid}")
            with contextlib.suppress(Exception):
                await self.client.stop_notify(uuid)
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
                    with contextlib.suppress(Exception):
                        await self.client.stop_notify(self.active_uuid)
                ok = await self._start_combined_with_fallbacks()
                if ok:
                    self.log("Notify riattivata.")
                    return True
            except Exception as e:
                self.log(f"(resubscribe fallita: {e})")
        # reconnect (senza unpair)
        if self.midstream_reconnects < MAX_MIDSTREAM_RECONNECTS:
            self.midstream_reconnects += 1
            self.log("Watchdog: riconnessione a caldo…")
            try:
                await self._hard_close(do_unpair=False)
                await self._connect_once()
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
            await self._connect_once()
        except Exception as e:
            self.uiq.put(("connect_failed", self.cfg.id, str(e), self.generation))
            self.log(f"Errore connessione: {e}")
            return

        # barriera: partire insieme
        try:
            self.log("In attesa dell’altro device…")
            self.barrier.wait(timeout=BARRIER_TIMEOUT_S)
        except Exception:
            self.uiq.put(("connect_failed", self.cfg.id, "Barrier timeout", self.generation))
            self.log("⚠️ Barriera non raggiunta: chiudo per retry coordinato.")
            await self._hard_close(do_unpair=False)
            return

        await self._start_bat_notify()
        ok = await self._start_combined_with_fallbacks()
        if not ok:
            self.uiq.put(("connect_failed", self.cfg.id, "Combined stream non disponibile", self.generation))
            self.log("⚠️ Nessuna stream accesa (combined). Chiudo.")
            await self._hard_close(do_unpair=False)
            return

        while not self.stop_event.is_set():
            ok = await self._ensure_streaming()
            if not ok:
                break
            await asyncio.sleep(0.2)

        await self._hard_close(do_unpair=False)
        self.log("Chiuso.")

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.run_async())
        finally:
            with contextlib.suppress(Exception): loop.stop()
            with contextlib.suppress(Exception): loop.close()

# ===================== APP (UI + Coordinatore) =====================
class App:
    def __init__(self, root):
        self.root = root
        root.title("STB_PRO dual — ACC/GYR live")

        # threading/stato
        self.uiq = queue.Queue()
        self.stop_event = threading.Event()
        self.workers = []
        self.resolver = None
        self.prepairer = None
        self.barrier = None
        self.ready = set()
        self.connected = set()
        self.closing = False
        self.retry_count = 0
        self.generation = 0

        # timeline globale
        self.t0 = None
        self.t_last_global = 0

        # CSV bins e batteria
        self.csv_bins = {1:{}, 2:{}}
        self.bat_filters = {1:SlewEMA(), 2:SlewEMA()}
        self.csv_path = None

        # ===== Top bar =====
        top = ttk.Frame(root, padding=6); top.pack(fill="x")
        self.btn_conn = ttk.Button(top, text="Connetti", command=self.on_connect)
        self.btn_stop = ttk.Button(top, text="Stop", state="disabled", command=self.on_stop)
        self.btn_conn.pack(side="left", padx=(0,6)); self.btn_stop.pack(side="left")
        self.lbl_gen = ttk.Label(top, text="Stato generale: Pronto"); self.lbl_gen.pack(side="left", padx=14)
        self.lbl_s1  = ttk.Label(top, text="Stato #1: —"); self.lbl_s1.pack(side="left", padx=10)
        self.lbl_b1  = ttk.Label(top, text="Batteria #1: —"); self.lbl_b1.pack(side="left", padx=6)
        self.lbl_s2  = ttk.Label(top, text="Stato #2: —"); self.lbl_s2.pack(side="left", padx=10)
        self.lbl_b2  = ttk.Label(top, text="Batteria #2: —"); self.lbl_b2.pack(side="left", padx=6)

        # ===== Corpo: grafici + tabelle =====
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

        # buffer plotting
        self.buff = {
            1: {k: deque(maxlen=TIMEWINDOW_MS) for k in ["t","ax","ay","az","gx","gy","gz"]},
            2: {k: deque(maxlen=TIMEWINDOW_MS) for k in ["t","ax","ay","az","gx","gy","gz"]},
        }
        self.lines = {}
        for dev_id, ax_acc, ax_gyr in [(1,self.ax11,self.ax21),(2,self.ax12,self.ax22)]:
            (lax,) = ax_acc.plot([], [], label="ax");  lax.set_antialiased(False)
            (lay,) = ax_acc.plot([], [], label="ay");  lay.set_antialiased(False)
            (laz,) = ax_acc.plot([], [], label="az");  laz.set_antialiased(False); ax_acc.legend(loc="upper left")
            (lgx,) = ax_gyr.plot([], [], label="gx");  lgx.set_antialiased(False)
            (lgy,) = ax_gyr.plot([], [], label="gy");  lgy.set_antialiased(False)
            (lgz,) = ax_gyr.plot([], [], label="gz");  lgz.set_antialiased(False); ax_gyr.legend(loc="upper left")
            self.lines[dev_id] = {"ax":lax,"ay":lay,"az":laz,"gx":lgx,"gy":lgy,"gz":lgz}

        # Scheduler state
        self._last_plot_t  = 0.0
        self._last_tbl_t   = 0.0
        self._last_ylim_t  = {1:0.0, 2:0.0}

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._after = root.after(REFRESH_TICK_MS, self.refresh)

    # ===== UI helpers =====
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

    # ===== Pulsanti =====
    def on_connect(self):
        if self.closing: return
        time.sleep(COOLDOWN_AFTER_STOP_S)
        self.generation += 1
        self._set_general("Risolvo i device…")
        self.btn_conn.configure(state="disabled"); self.btn_stop.configure(state="disabled")
        self._set_state(1, "Risoluzione…"); self._set_state(2, "Risoluzione…")
        self._set_bat(1, None, None); self._set_bat(2, None, None)
        self.ready.clear(); self.connected.clear(); self.stop_event.clear()
        self.csv_bins = {1:{}, 2:{}}
        self.bat_filters = {1:SlewEMA(), 2:SlewEMA()}
        self.csv_path = (Path.home()/ "Desktop" / f"stbpro_dual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        self.t_last_global = self._global_last_time()
        self.t0 = time.time() - (self.t_last_global + 0.02)
        # avvia resolver
        self.resolver = Resolver(ADDR_1, ADDR_2, self.uiq, self.stop_event)
        self.resolver.start()

    def _start_workers(self, r1: Resolved, r2: Resolved):
        self._set_general("Connessione… (post-pair)")
        self._set_state(1, f"Connessione a {r1.device.address}")
        self._set_state(2, f"Connessione a {r2.device.address}")
        self.barrier = threading.Barrier(2)
        w1 = BLEWorker(DevCfg(1, r1.device, COMBINED_UUID_1), self.uiq, self.stop_event,
                       self.barrier, self._set_state, self.generation)
        w2 = BLEWorker(DevCfg(2, r2.device, COMBINED_UUID_2), self.uiq, self.stop_event,
                       self.barrier, self._set_state, self.generation)
        self.workers = [w1, w2]
        for w in self.workers: w.start()

    def _abort_and_retry_later(self, reason=""):
        self.stop_event.set()
        if self.prepairer:
            with contextlib.suppress(Exception): self.prepairer.join(timeout=1.2)
            self.prepairer = None
        for w in self.workers:
            with contextlib.suppress(Exception): w.join(timeout=1.8)
        self.workers = []
        self.stop_event.clear()
        self.retry_count += 1
        self._set_general(f"Retry {self.retry_count}: {reason}. Nuova risoluzione…")
        def _restart():
            if self.closing: return
            self.resolver = Resolver(ADDR_1, ADDR_2, self.uiq, self.stop_event)
            self.resolver.start()
        self.root.after(int(RETRY_BACKOFF_S*1000), _restart)

    def on_stop(self):
        if self.closing: return
        try: self.root.after_cancel(self._after)
        except Exception: pass
        self.stop_event.set()
        if self.resolver:
            with contextlib.suppress(Exception): self.resolver.join(timeout=1.0)
            self.resolver = None
        if self.prepairer:
            with contextlib.suppress(Exception): self.prepairer.join(timeout=1.0)
            self.prepairer = None
        for w in self.workers:
            with contextlib.suppress(Exception): w.join(timeout=3.0)
        self.workers = []
        with contextlib.suppress(Exception): self._save_merged_csv_0p5s()
        self._set_state(1, "Disconnesso."); self._set_state(2, "Disconnesso.")
        self._set_general("Arrestato")
        self.btn_conn.configure(state="normal"); self.btn_stop.configure(state="disabled")
        self._after = self.root.after(REFRESH_TICK_MS, self.refresh)

    def on_close(self):
        if self.closing: return
        self.closing = True
        try: self.root.after_cancel(self._after)
        except Exception: pass
        self._set_general("Chiusura…")
        self.stop_event.set()
        if self.resolver:
            with contextlib.suppress(Exception): self.resolver.join(timeout=1.0)
        if self.prepairer:
            with contextlib.suppress(Exception): self.prepairer.join(timeout=1.0)
        for w in self.workers:
            with contextlib.suppress(Exception): w.join(timeout=3.0)
        with contextlib.suppress(Exception): self._save_merged_csv_0p5s()
        with contextlib.suppress(Exception): self.root.destroy()

    # ===== Main refresh =====
    def refresh(self):
        now = time.time()
        drained = 0
        gen = self.generation
        try:
            while drained < MAX_QUEUE_DRAIN_PER_TICK:
                item = self.uiq.get_nowait()
                drained += 1
                kind = item[0]

                if kind == "resolve_error":
                    _, msg = item
                    self._set_state(1, "Risoluzione fallita"); self._set_state(2, "Risoluzione fallita")
                    self._abort_and_retry_later(msg)

                elif kind == "resolved_both":
                    _, r1, r2 = item
                    self._set_general("Accoppiamento sequenziale…")
                    self._set_state(1, "Pair in corso…"); self._set_state(2, "Pair in corso…")
                    self.prepairer = PrePairer(r1, r2, self.uiq, self.stop_event)
                    self.prepairer.start()

                elif kind == "pair_status":
                    _, dev_id, msg = item
                    self._set_state(dev_id, msg)

                elif kind == "prepair_done":
                    _, r1, r2 = item
                    self._start_workers(r1, r2)

                elif kind == "connected":
                    _, dev_id, g = item
                    if g != gen: continue
                    self.connected.add(dev_id)
                    if len(self.connected) == 2:
                        self._set_general("Connessi. In attesa dei primi dati…")

                elif kind == "connect_failed":
                    _, dev_id, why, g = item
                    if g != gen: continue
                    self._set_state(dev_id, f"Connessione fallita: {why}")
                    self._abort_and_retry_later(f"Device #{dev_id}: {why}")

                elif kind == "ready":
                    _, dev_id, g = item
                    if g != gen: continue
                    self.ready.add(dev_id)
                    if len(self.ready) == 2:
                        self.btn_stop.configure(state="normal")
                        self._set_general("Streaming")

                elif kind == "bat":
                    _, dev_id, pct, mv, tnow, g = item
                    if g != gen: continue
                    if pct is not None: pct = clamp(pct, 0.0, 100.0)
                    filt = self.bat_filters[dev_id]
                    if tnow - filt.last_ui_t >= BAT_UPDATE_MIN_DT or filt.last_ui_t == 0.0:
                        spct = filt.update(pct, tnow)
                        self._set_bat(dev_id, spct, mv)

                elif kind == "accgyr":
                    _, dev_id, t_host, ts_ble, ax, ay, az, gx, gy, gz, g = item
                    if g != gen: continue
                    if self.t0 is None:
                        self.t0 = time.time() - (self._global_last_time() + 0.02)
                    t_s = max(0.0, t_host - self.t0)
                    B = self.buff[dev_id]
                    B["t"].append(t_s)
                    B["ax"].append(ax); B["ay"].append(ay); B["az"].append(az)
                    B["gx"].append(gx); B["gy"].append(gy); B["gz"].append(gz)
                    # CSV 0.5 s
                    t_ms = int(round(t_s*1000))
                    bin_ms = (t_ms // CSV_BIN_MS) * CSV_BIN_MS
                    self.csv_bins[dev_id][bin_ms] = [ax, ay, az, gx, gy, gz]

                else:
                    pass
        except queue.Empty:
            pass

        # Tabelle (throttle)
        if (now - self._last_tbl_t) >= TABLE_INTERVAL_S:
            for dev_id, tree in [(1, self.tree1), (2, self.tree2)]:
                B = self.buff[dev_id]
                if not B["t"]: continue
                t_s = B["t"][-1]
                ax, ay, az = B["ax"][-1], B["ay"][-1], B["az"][-1]
                gx, gy, gz = B["gx"][-1], B["gy"][-1], B["gz"][-1]
                tree.insert("", "end", values=(f"{t_s:7.2f}", ax, ay, az, f"{gx:.1f}", f"{gy:.1f}", f"{gz:.1f}"))
                ch = tree.get_children()
                if len(ch) > 50:
                    tree.delete(ch[0])
            self._last_tbl_t = now

        # Grafici (throttle + decimazione)
        if (now - self._last_plot_t) >= PLOT_INTERVAL_S:
            for dev_id, ax_acc, ax_gyr in [(1,self.ax11,self.ax21),(2,self.ax12,self.ax22)]:
                B = self.buff[dev_id]; t=list(B["t"])
                if not t: continue
                tmax = t[-1]; tmin = max(0.0, tmax - TIMEWINDOW_MS/1000.0)
                # trova i0
                i0 = 0
                for k in range(len(t)-1, -1, -1):
                    if t[k] < tmin: i0 = k+1; break
                tf = t[i0:]
                if not tf: continue
                step = max(1, len(tf)//MAX_POINTS_PER_LINE)
                tf2 = tf[::step]

                # ACC
                ax = list(B["ax"])[i0:][::step]
                ay = list(B["ay"])[i0:][::step]
                az = list(B["az"])[i0:][::step]
                L = self.lines[dev_id]
                L["ax"].set_data(tf2, ax); L["ay"].set_data(tf2, ay); L["az"].set_data(tf2, az)
                ax_acc.set_xlim(max(0, tf2[0]), max(tf2[-1], 3))
                if (now - self._last_ylim_t[dev_id]) >= YLIM_INTERVAL_S:
                    ymin = min(min(ax), min(ay), min(az)); ymax = max(max(ax), max(ay), max(az))
                    pad = max(50.0, 0.1*(ymax-ymin+1))
                    ax_acc.set_ylim(ymin-pad, ymax-pad+2*pad)

                # GYR
                gx = list(B["gx"])[i0:][::step]
                gy = list(B["gy"])[i0:][::step]
                gz = list(B["gz"])[i0:][::step]
                L["gx"].set_data(tf2, gx); L["gy"].set_data(tf2, gy); L["gz"].set_data(tf2, gz)
                ax_gyr.set_xlim(max(0, tf2[0]), max(tf2[-1], 3))
                if (now - self._last_ylim_t[dev_id]) >= YLIM_INTERVAL_S:
                    ymin = min(min(gx), min(gy), min(gz)); ymax = max(max(gx), max(gy), max(gz))
                    pad = max(5.0, 0.1*(ymax-ymin+1))
                    ax_gyr.set_ylim(ymin-pad, ymax-pad+2*pad)

                if (now - self._last_ylim_t[dev_id]) >= YLIM_INTERVAL_S:
                    self._last_ylim_t[dev_id] = now

            self.canvas.draw_idle()
            self._last_plot_t = now

        if not self.closing:
            self._after = self.root.after(REFRESH_TICK_MS, self.refresh)

    # ===== CSV (0.5 s, hold-last) =====
    def _save_merged_csv_0p5s(self):
        b1 = self.csv_bins[1]; b2 = self.csv_bins[2]
        if not b1 and not b2:
            print("→ Nessun dato, CSV non creato."); return
        max_bin = 0
        if b1: max_bin = max(max_bin, max(b1.keys()))
        if b2: max_bin = max(max_bin, max(b2.keys()))
        last1 = [None]*6; last2 = [None]*6
        if self.csv_path is None:
            self.csv_path = Path.home() / "Desktop" / f"stbpro_dual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(self.csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["t_s","ax#1","ay#1","az#1","gx#1","gy#1","gz#1",
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
