# stbpro_dual_sync_ui_v6_win_resolve.py
# - Windows: risoluzione robusta via scan multipli (match score + RSSI)
# - Connect sequenziale (prima #1 poi #2), con re-scan prima di ogni tentativo
# - Filtro "connectable" preferenziale ma NON bloccante
# - Start stream solo dopo primo campione da entrambi (barriera "ready")
# - GUI invariata: 4 grafici a sinistra (ACC/GYR #1 e #2), 2 tabelle a destra
# - Stati per device + stato generale + batteria smussata
# - CSV con bin da 0.5 s (hold-last-value), timeline continua tra run
# - X in secondi, finestra 6 s (TIMEWINDOW_MS = 60_00)

import sys, asyncio, contextlib, struct, time, csv, os, threading, queue
from collections import deque, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from bleak import BleakScanner, BleakClient

# ===================== CONFIG =====================
# Indirizzi/hint attuali (verranno usati come preferenza, ma non "a morte")
ADDR_1 = "DA:F9:0A:9C:AD:07"  # STB_PRO #1
ADDR_2 = "E4:9D:3B:F9:E1:A0"  # STB_PRO #2

# UUID combined "note" (se le conosci): usa autodetect se non funzionano
COMBINED_UUID_1 = "00c00000-0001-11e1-ac36-0002a5d5c51b"  # #1 noto (se differente, cambia)
COMBINED_UUID_2 = "00e00000-0001-11e1-ac36-0002a5d5c51b"  # #2 noto (se differente, cambia)

# BlueST
BLUEST_SERVICE = "00000000-0001-11e1-9ab4-0002a5d5c51b"
BAT_UUID       = "00020000-0001-11e1-ac36-0002a5d5c51b"

# Candidati fallback se la preferita non manda dati
COMBINED_CANDIDATES = [
    "00c00000-0001-11e1-ac36-0002a5d5c51b",
    "00e00000-0001-11e1-ac36-0002a5d5c51b",
    "00190000-0001-11e1-ac36-0002a5d5c51b",
    "00000100-0001-11e1-ac36-0002a5d5c51b",
    "00000014-0002-11e1-ac36-0002a5d5c51b",
]

# Connessione/Retry
CONNECT_TIMEOUT_S      = 10
CONNECT_RETRIES        = 5
RETRY_BACKOFF_BASE_S   = 1.5
POST_CONNECT_WAIT_S    = 1.0

# Scansioni per risolvere i device
RESOLVE_TOTAL_BUDGET_S = 18.0  # tempo massimo dedicato a risolvere entrambi
RESOLVE_PASS_S         = 3.0   # durata di una singola passata di scan
RESOLVE_PAUSE_S        = 0.8   # pausa tra passate

# GUI
TIMEWINDOW_MS          = 60_00  # 6 s
REFRESH_MS             = 60

# CSV
CSV_BIN_MS             = 500

# Start stream: primo dato entro...
START_DATA_TIMEOUT_S   = 2.5

# Watchdog streaming
NO_DATA_WATCHDOG_S     = 5.0
MAX_NOTIFY_RESETS      = 2
MAX_MIDSTREAM_RECONNECTS = 1

# Batteria smoothing
BAT_UPDATE_MIN_DT      = 1.5
BAT_EMA_ALPHA          = 0.08
BAT_MAX_STEP           = 1.0

# ===================== GUI deps =====================
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ===================== Utils =====================
def clamp(v, lo, hi): return max(lo, min(hi, v))

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

# ===================== Scan/Risolve (Windows-centrico ma cross-OS) =====================
def _adv_name(adv):
    return (getattr(adv, "local_name", None) or "").lower()

def _dev_name(dev):
    return (getattr(dev, "name", None) or "").lower()

def _is_connectable(adv) -> bool:
    try:
        return bool(getattr(adv, "is_connectable", True))
    except Exception:
        return True

def _match_score(hint: str, dev, adv) -> int:
    """3=match address esatto; 2=match per suffisso (ultime 6); 1=nome contiene 'stb_pro'; 0=altro"""
    h = (hint or "").lower()
    addr = (getattr(dev, "address", "") or "").lower()
    if h:
        if addr == h:
            return 3
        if len(h) >= 6 and addr.endswith(h[-6:]):
            return 2
    nm = _dev_name(dev) or _adv_name(adv)
    if "stb_pro" in nm:
        return 1
    return 0

async def _scan_pass(pass_s: float):
    async with BleakScanner() as scanner:
        await asyncio.sleep(pass_s)
        pairs = list(scanner.discovered_devices_and_advertisement_data.values())
    # ordina per RSSI
    try:
        pairs.sort(key=lambda p: getattr(p[1], "rssi", -9999), reverse=True)
    except Exception:
        pass
    return pairs

async def resolve_two_targets(hint1: str, hint2: str, total_budget_s: float, pass_s: float, pause_s: float, log_cb):
    """
    Tenta di risolvere due target (#1 e #2) entro 'total_budget_s', con N passate da 'pass_s'.
    Sceglie il candidato con miglior punteggio (score) e, a parità, RSSI maggiore.
    Preferisce connectable, ma se non ce n'è, accetta anche non-connectable.
    Ritorna: (cand1, cand2) come oggetti BLEDevice (o None), più descrizione testuale.
    """
    best1 = None; best2 = None
    best1_score = -1; best2_score = -1
    best1_rssi = -9999; best2_rssi = -9999
    t0 = time.time()

    while time.time() - t0 < total_budget_s:
        pairs = await _scan_pass(pass_s)
        if not pairs:
            log_cb(f"Scan: nessun device visto in questa passata ({pass_s}s).")
        # primo giro: considera solo connectable
        for connectable_only in (True, False):
            for dev, adv in pairs:
                if connectable_only and not _is_connectable(adv):
                    continue
                rssi = getattr(adv, "rssi", -9999)
                s1 = _match_score(hint1, dev, adv)
                s2 = _match_score(hint2, dev, adv)
                if s1 > 0 and (s1 > best1_score or (s1 == best1_score and rssi > best1_rssi)):
                    best1, best1_score, best1_rssi = dev, s1, rssi
                if s2 > 0 and (s2 > best2_score or (s2 == best2_score and rssi > best2_rssi)):
                    best2, best2_score, best2_rssi = dev, s2, rssi
            # se entrambi trovati in connectable-only, fermati
            if connectable_only and best1 and best2:
                break
        if best1 and best2:
            break
        await asyncio.sleep(pause_s)

    def _desc(dev, score, rssi):
        if not dev: return "—"
        return f"{dev.address} (score={score}, RSSI={rssi}, name={dev.name or '—'})"

    return best1, best2, _desc(best1, best1_score, best1_rssi), _desc(best2, best2_score, best2_rssi)

# ===================== BLE Worker =====================
@dataclass
class DevCfg:
    id: int
    hint: str
    combined_uuid: str | None

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
        self.ble_target = None  # BLEDevice risolto

        # watchdog
        self.last_data_t = 0.0
        self.notify_resets = 0
        self.midstream_reconnects = 0
        self.started_once = False

    def log(self, msg): self.status_cb(self.cfg.id, msg)

    async def _rescan_and_pick_target(self):
        # piccolo scan dedicato per rinfrescare la BLEDevice prima della connect
        dev1, _, _, _ = await resolve_two_targets(self.cfg.hint, "", 4.0, 2.0, 0.6, lambda _: None)
        self.ble_target = dev1 if dev1 else self.ble_target

    async def _connect_with_retries(self):
        last_exc = None
        for attempt in range(1, CONNECT_RETRIES + 1):
            # re-scan corto per aggiornare oggetto BLEDevice (se disponibile)
            await self._rescan_and_pick_target()

            target_for_log = self.cfg.hint
            target_arg = self.ble_target if self.ble_target else self.cfg.hint

            if isinstance(target_arg, str):
                self.log(f"Connessione (via string) a {target_for_log} (tentativo {attempt}/{CONNECT_RETRIES})…")
            else:
                self.log(f"Connessione (via BLEDevice) a {target_arg.address} "
                         f"({target_arg.name or '—'}) (tentativo {attempt}/{CONNECT_RETRIES})…")

            cl = BleakClient(target_arg, disconnected_callback=lambda c: self.log("Disconnesso."))
            try:
                # connect con hard-timeout
                task = asyncio.create_task(cl.connect())
                done, _ = await asyncio.wait({task}, timeout=CONNECT_TIMEOUT_S)
                if not done:
                    self.log("Timeout connect: forzo disconnect e annullo.")
                    with contextlib.suppress(Exception):
                        await cl.disconnect()
                    with contextlib.suppress(Exception):
                        task.cancel(); await task
                    raise asyncio.TimeoutError("Connect deadline exceeded")

                # solleva eccezione se fallita
                await task

                # pairing opzionale
                if sys.platform == "win32":
                    try:
                        paired = await cl.is_paired()
                    except Exception:
                        paired = True
                    if not paired:
                        with contextlib.suppress(Exception):
                            ok = await cl.pair(protection_level=1)
                            self.log(f"Pairing esito: {ok}")

                await asyncio.sleep(POST_CONNECT_WAIT_S)
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(cl.get_services(), timeout=5)

                self.client = cl
                self.log("Connesso.")
                return

            except Exception as e:
                last_exc = e
                self.log(f"Errore: {type(e).__name__}: {e}")
                with contextlib.suppress(Exception):
                    await cl.disconnect()
                if attempt < CONNECT_RETRIES:
                    backoff = RETRY_BACKOFF_BASE_S * attempt
                    self.log(f"Riprovo tra {backoff:.1f}s…")
                    await asyncio.sleep(backoff)

        raise last_exc if last_exc else RuntimeError("Connessione fallita")

    # callbacks
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
            if not got_first.is_set():
                got_first.set()
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
        # reconnect a caldo
        if self.midstream_reconnects < MAX_MIDSTREAM_RECONNECTS:
            self.midstream_reconnects += 1
            self.log("Watchdog: riconnessione a caldo…")
            try:
                with contextlib.suppress(Exception):
                    await self.client.disconnect()
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

        # attesa dell'altro device
        try:
            self.log("In attesa dell’altro device…")
            self.barrier.wait(timeout=20)
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

        # cleanup
        with contextlib.suppress(Exception):
            if self.client:
                if self.active_uuid:
                    await self.client.stop_notify(self.active_uuid)
                await self.client.stop_notify(BAT_UUID)
                await self.client.disconnect()
        self.log("Chiuso.")

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.run_async())
        finally:
            with contextlib.suppress(Exception): loop.stop()
            with contextlib.suppress(Exception): loop.close()

# ===================== APP =====================
import tkinter as tk
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

class App:
    def __init__(self, root):
        self.root = root
        root.title("STB_PRO dual — ACC/GYR live")

        # threading/stato
        self.uiq = queue.Queue()
        self.stop_event = threading.Event()
        self.workers = []
        self.barrier = None
        self.ready = set()
        self.closing =
