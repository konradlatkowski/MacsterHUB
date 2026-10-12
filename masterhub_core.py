#!/usr/bin/env python3
"""MasterHUB — wspólny rdzeń HID i konsola, Python 3.10+.

Zależności: python -m pip install hidapi Pillow
Start:      python masterhub_core.py
Pomoc:      python masterhub_core.py --help

Obsługujemy: 15 klawiszy IPS, gałkę IPS M131E, 3 gałki M0 i 5 suwaków.
Import tego pliku nie otwiera USB ani nie uruchamia wątków.

GUI powinno utworzyć MasterHub, wywołać start(), regularnie odbierać
get_events() i na zamknięcie wywołać stop(). Wszystkie operacje HID danego
urządzenia należą do jednego wątku; GUI nigdy nie korzysta z uchwytu HID.
set_key_image()/set_dial_image() zwracają Future, bez blokowania GUI.
"""
from __future__ import annotations

import argparse
import io
import json
import queue
import shlex
import struct
import sys
import threading
import time
from concurrent.futures import Future
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


# 1. Protokół: liczby przeniesione z działających skryptów i sprawdzonego SDK.
VID = 0x2516
REPORT_SIZE = 320                  # wraz z Report ID; nie dodajemy bajtu 00
CHUNK_SIZE = REPORT_SIZE - 8       # 312 bajtów obrazu w każdym raporcie


class Module(str, Enum):
    KEYS = "keys"
    DIAL = "dial"
    KNOBS = "knobs"
    SLIDERS = "sliders"


@dataclass(frozen=True)
class DeviceSpec:
    module: Module
    name: str
    pid: int
    software_command: int | None = None
    image_command: int | None = None
    image_size: tuple[int, int] | None = None
    quality: int = 90


SPECS = {
    0x01FE: DeviceSpec(Module.KEYS, "15-Key IPS", 0x01FE, 0x3A, 0x36, (72, 72)),
    0x0206: DeviceSpec(Module.DIAL, "1x Dial IPS", 0x0206, 0x49, 0x45, (240, 240), 95),
    0x0202: DeviceSpec(Module.KNOBS, "3x Knob", 0x0202),
    0x0200: DeviceSpec(Module.SLIDERS, "5x Slider", 0x0200),
}


@dataclass(frozen=True)
class DeviceInfo:
    """ID identyfikuje połączenie; numer seryjny pozwala wybrać egzemplarz."""
    id: str
    module: Module
    name: str
    pid: int
    serial: str
    path: bytes


@dataclass(frozen=True)
class Event:
    """Jednolity format dla terminala, GUI i przyszłych przypisań akcji.

    action: connected/disconnected/pressed/released/rotated/slider_changed/image_sent/error/raw
    control: numer od 1 (klawisz 1..15, gałka 1..3, gałka IPS = 1, suwak 1..5)
    direction: left/right wyłącznie dla rotated
    value: pozycja suwaka 0..100, wyłącznie dla slider_changed
    timestamp: czas Unix; raw: cały raport, przydatny w diagnostyce
    """
    timestamp: float
    device_id: str
    module: Module
    serial: str
    action: str
    control: int | None = None
    direction: str | None = None
    value: int | None = None
    message: str = ""
    raw: bytes = b""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["module"] = self.module.value
        data["raw"] = self.raw.hex(" ")
        return data


# 2. Dekoder jest niezależny od HID. Można go testować nagranymi raportami.
class ReportDecoder:
    def __init__(self, info: DeviceInfo):
        self.info = info
        self.pressed: set[int] = set()
        self.slider_values: tuple[int, ...] | None = None

    def event(self, action: str, **fields: Any) -> Event:
        return Event(time.time(), self.info.id, self.info.module,
                     self.info.serial, action, **fields)

    def _button(self, number: int, state: int, raw: bytes,
                release: bool = False) -> list[Event]:
        if state == 1 and number not in self.pressed:
            self.pressed.add(number)
            return [self.event("pressed", control=number, raw=raw)]
        if state == 0 and number in self.pressed:
            self.pressed.remove(number)
            if release:
                return [self.event("released", control=number, raw=raw)]
        # Powtarzane stany przytrzymanego przycisku nie są kolejnymi kliknięciami.
        # FF (brak zdarzenia) nie jest puszczeniem przycisku.
        return []

    def decode(self, data: bytes) -> list[Event]:
        raw = bytes(data)
        if len(raw) < 4 or raw[0] != 0x01:
            return [self.event("raw", message="Nieznany nagłówek", raw=raw)]
        length = int.from_bytes(raw[2:4], "little")
        if length > len(raw) - 4:
            return [self.event("raw", message="Niepełny raport", raw=raw)]
        payload = raw[4:4 + length]
        events: list[Event] = []
        module = self.info.module
        if (module == Module.SLIDERS and raw[1] == 0x2A
                and len(payload) >= 7 and payload[:2] == b"\x02\x05"):
            values = tuple(payload[2:7])
            if any(value > 100 for value in values):
                return [self.event("raw", message="Suwak poza potwierdzonym zakresem 0..100", raw=raw)]
            for number, value in enumerate(values, 1):
                if self.slider_values is None or self.slider_values[number - 1] != value:
                    events.append(self.event("slider_changed", control=number, value=value, raw=raw))
            # Raport zawiera stan wszystkich pięciu suwaków. Pierwszy emituje
            # pięć pozycji początkowych; kolejne tylko rzeczywiste zmiany.
            self.slider_values = values
            return events
        if module == Module.KEYS and len(payload) >= 17 and payload[:2] == b"\x02\x0f":
            for number, state in enumerate(payload[2:17], 1):
                events.extend(self._button(number, state, raw))
            return events
        if module == Module.KNOBS and len(payload) >= 5:
            if payload[:2] == b"\x00\x03":
                for number, value in enumerate(payload[2:5], 1):
                    if value in (0, 1):
                        events.append(self.event("rotated", control=number,
                                      direction="right" if value == 1 else "left", raw=raw))
                # Każdy raport obrotu jest kolejnym krokiem, także identyczny.
                return events
            if payload[:2] == b"\x03\x03":
                for number, state in enumerate(payload[2:5], 1):
                    events.extend(self._button(number, state, raw))
                return events
        if module == Module.DIAL and len(payload) >= 3:
            # Bieżący SDK: typ 3 = obrót, typ 4 = przycisk.
            # Aplikacja producenta rozpoznaje także starsze typy 0 i 1.
            kind, value = payload[0], payload[2]
            if kind in (0, 3) and value in (0, 1):
                return [self.event("rotated", control=1,
                                   direction="right" if value == 0 else "left", raw=raw)]
            if kind in (1, 4) and value in (0, 1):
                return self._button(1, value, raw, release=True)
        return [self.event("raw", message=f"Nieznany payload, kanał {raw[1]:02X}", raw=raw)]


# 3. Obrazy: ten sam nagłówek co w set_icon.py i set_dial_image.py.
def prepare_image(path: str | Path, spec: DeviceSpec, quality: int | None = None) -> bytes:
    if spec.image_size is None:
        raise ValueError("Ten moduł nie ma obsługi obrazu")
    quality = spec.quality if quality is None else quality
    if not 1 <= quality <= 100:
        raise ValueError("Jakość JPEG musi wynosić 1..100")
    from PIL import Image, ImageOps
    with Image.open(path) as source:
        image = ImageOps.fit(ImageOps.exif_transpose(source).convert("RGB"),
                             spec.image_size, method=Image.Resampling.LANCZOS)
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=quality, progressive=False)
        return buffer.getvalue()


def image_reports(jpeg: bytes, spec: DeviceSpec, control: int = 1):
    if spec.image_command is None:
        raise ValueError("Ten moduł nie ma obsługi obrazu")
    if spec.module == Module.KEYS and not 1 <= control <= 15:
        raise ValueError("Numer klawisza musi wynosić 1..15")
    if spec.module == Module.DIAL and control != 1:
        raise ValueError("Moduł Dial ma jeden ekran")
    if not jpeg.startswith(b"\xff\xd8\xff\xe0"):
        raise ValueError("Wymagany JPEG JFIF: FF D8 FF E0")
    if len(jpeg) > CHUNK_SIZE * 65536:
        raise ValueError("Obraz przekracza zakres numeracji fragmentów")
    target = control - 1 if spec.module == Module.KEYS else 0
    for sequence, offset in enumerate(range(0, len(jpeg), CHUNK_SIZE)):
        chunk = jpeg[offset:offset + CHUNK_SIZE]
        final = int(offset + len(chunk) == len(jpeg))
        header = struct.pack("<BBHHBB", 0x02, spec.image_command,
                             sequence, len(chunk), target, final)
        yield header + chunk + bytes(CHUNK_SIZE - len(chunk))


@dataclass(frozen=True)
class ImageResult:
    device_id: str
    control: int
    jpeg_bytes: int
    reports: int


@dataclass
class _ImageJob:
    path: Path
    control: int
    quality: int | None
    future: Future


# 4. Jeden właściciel HID na urządzenie. Kolejka zapobiega przeplataniu obrazów.
class _DeviceWorker:
    def __init__(self, info: DeviceInfo, backend: Any, events: queue.Queue, raw: bool):
        self.info, self.backend, self.events, self.raw = info, backend, events, raw
        self.spec = SPECS[info.pid]
        self.decoder = ReportDecoder(info)
        self.jobs: queue.Queue[_ImageJob] = queue.Queue()
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.accepting = True
        self.thread = threading.Thread(target=self._run, name=f"HID-{info.id}", daemon=True)

    def emit(self, action: str, **fields: Any):
        self.events.put(self.decoder.event(action, **fields))

    def submit(self, job: _ImageJob):
        with self.lock:
            if not self.accepting:
                raise RuntimeError(f"Urządzenie niedostępne: {self.info.name}")
            self.jobs.put(job)

    def stop(self):
        with self.lock:
            self.accepting = False
            self.stopping.set()

    def _send_image(self, device: Any, job: _ImageJob):
        if not job.future.set_running_or_notify_cancel():
            return
        try:
            # Przygotowanie JPEG też odbywa się poza wątkiem GUI.
            jpeg = prepare_image(job.path, self.spec, job.quality)
            count = 0
            for packet in image_reports(jpeg, self.spec, job.control):
                if self.stopping.is_set():
                    raise InterruptedError("Wysyłanie przerwane przy zamykaniu programu")
                try:
                    written = device.write(packet)
                except OSError as error:
                    raise ConnectionError(f"Zapis HID: {error}") from error
                if written != REPORT_SIZE:
                    raise ConnectionError(f"Niepełny zapis HID: {written}/{REPORT_SIZE}")
                count += 1
            result = ImageResult(self.info.id, job.control, len(jpeg), count)
            self.emit("image_sent", control=job.control,
                      message=f"JPEG {len(jpeg)} B, {count} raportów; HIDAPI przyjęło zapis")
            job.future.set_result(result)
        except Exception as error:
            job.future.set_exception(error)
            # Zły plik nie zatrzymuje monitora. Utrata HID kończy to połączenie.
            if isinstance(error, ConnectionError):
                raise
            self.emit("error", message=f"Obraz: {error}")

    def _run(self):
        device = None
        connected = False
        failure: Exception = RuntimeError("Połączenie zostało zamknięte")
        try:
            device = self.backend.device()
            device.open_path(self.info.path)
            device.set_nonblocking(True)
            if self.spec.software_command is not None:
                report = bytes([0x03, self.spec.software_command, 0x01]) + bytes(29)
                written = device.send_feature_report(report)
                if written != 32:
                    raise ConnectionError(f"Software Mode: zapis {written}/32")
            connected = True
            self.emit("connected", message=self.info.name)
            while not self.stopping.is_set():
                # Odczyt jest nieblokujący, więc zadanie obrazu nie czeka na kliknięcie.
                data = device.read(256)
                if data:
                    packet = bytes(data)
                    decoded = self.decoder.decode(packet)
                    if self.raw and not any(e.action == "raw" for e in decoded):
                        self.emit("raw", raw=packet)
                    for event in decoded:
                        self.events.put(event)
                try:
                    job = self.jobs.get_nowait()
                except queue.Empty:
                    job = None
                if job is not None:
                    self._send_image(device, job)
                if not data and job is None:
                    self.stopping.wait(0.01)
        except Exception as error:
            failure = error
            self.emit("error", message=str(error))
        finally:
            self.stop()
            # Każda oczekująca Future kończy się, także gdy otwarcie HID się nie uda.
            while True:
                try:
                    job = self.jobs.get_nowait()
                except queue.Empty:
                    break
                if job.future.set_running_or_notify_cancel():
                    job.future.set_exception(failure)
            if device is not None:
                try:
                    device.close()
                except Exception as error:
                    self.emit("error", message=f"Zamykanie HID: {error}")
            if connected:
                self.emit("disconnected", message=self.info.name)
            # Software Mode pozostaje włączony: nie kasujemy grafiki na wyjściu.


# 5. Publiczne API. Tę klasę importuje przyszłe GUI.
class MasterHub:
    def __init__(self, modules=None, *, raw: bool = False, backend=None):
        self.modules = set(Module(m) for m in modules) if modules is not None else set(Module)
        self.raw = raw
        self._backend = backend         # wstrzyknięcie atrapy pozwala testować bez USB
        self._events: queue.Queue[Event] = queue.Queue()
        self._workers: dict[str, _DeviceWorker] = {}
        self._lock = threading.RLock()
        self._started = False

    @property
    def backend(self):
        if self._backend is None:
            import hid
            self._backend = hid
        return self._backend

    def discover(self) -> list[DeviceInfo]:
        found = {}
        for item in self.backend.enumerate(VID, 0):
            spec = SPECS.get(item["product_id"])
            # Consumer collection, usage 1 — wspólna ścieżka znanych modułów.
            if (spec is None or spec.module not in self.modules
                    or item.get("usage_page") != 0x0C or item.get("usage") != 1):
                continue
            path = item["path"]
            serial = item.get("serial_number") or ""
            identity = f"{spec.module.value}:{serial or path.hex()}"
            if identity in found and found[identity].path != path:
                identity += ":" + path.hex()  # nie łączymy dwóch różnych uchwytów
            found[identity] = DeviceInfo(identity, spec.module, spec.name, spec.pid, serial, path)
        return list(found.values())

    def start(self) -> list[DeviceInfo]:
        """Wykryj i uruchom moduły; wynik otwarcia przyjdzie jako Event.

        Po odłączeniu/podłączeniu USB wywołaj restart(). Automatyczne ponawianie
        połączenia będzie osobną funkcją kolejnej wersji.
        """
        with self._lock:
            if self._started:
                return self.devices()
            infos = self.discover()
            self._started = True
            for info in infos:
                worker = _DeviceWorker(info, self.backend, self._events, self.raw)
                self._workers[info.id] = worker
                worker.thread.start()
            return infos

    def devices(self) -> list[DeviceInfo]:
        """Aktualnie uruchomione próby połączenia; status pochodzi ze zdarzeń."""
        with self._lock:
            return [w.info for w in self._workers.values() if w.accepting]

    def get_event(self, timeout: float | None = None) -> Event:
        """Blokujące oczekiwanie; przy timeout brak zdarzenia = queue.Empty."""
        return self._events.get(timeout=timeout)

    def get_events(self, limit: int = 100) -> list[Event]:
        """Nieblokujące pobranie dla timera GUI, np. co 20 ms."""
        result = []
        for _ in range(limit):
            try:
                result.append(self._events.get_nowait())
            except queue.Empty:
                break
        return result

    def _image(self, module: Module, control: int, path: str | Path,
               serial: str | None, quality: int | None) -> Future:
        with self._lock:
            workers = [w for w in self._workers.values() if w.accepting
                       and w.info.module == module and (serial is None or w.info.serial == serial)]
            if len(workers) != 1:
                raise RuntimeError(f"Dostępne moduły {module.value}: {len(workers)}. "
                                   "Uruchom start(); przy kilku egzemplarzach podaj serial.")
            future: Future = Future()
            workers[0].submit(_ImageJob(Path(path), control, quality, future))
            return future

    def set_key_image(self, key: int, path: str | Path, *,
                      serial: str | None = None, quality: int | None = None) -> Future:
        if not 1 <= key <= 15:
            raise ValueError("Numer klawisza musi wynosić 1..15")
        return self._image(Module.KEYS, key, path, serial, quality)

    def set_dial_image(self, path: str | Path, *,
                       serial: str | None = None, quality: int | None = None) -> Future:
        return self._image(Module.DIAL, 1, path, serial, quality)

    def stop(self):
        """Zatrzymaj odczyt i zamknij uchwyty; można wywołać wielokrotnie."""
        with self._lock:
            workers = list(self._workers.values())
            for worker in workers:
                worker.stop()
            # Uchwytu nie zamykamy z obcego wątku podczas operacji HID.
            for worker in workers:
                worker.thread.join(timeout=5)
            pending = [w.info.name for w in workers if w.thread.is_alive()]
            if pending:
                raise RuntimeError("Operacja HID nie zakończyła się przy zamykaniu: "
                                   + ", ".join(pending))
            self._workers.clear()
            self._started = False

    def restart(self) -> list[DeviceInfo]:
        self.stop()
        return self.start()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


# 6. Terminal: wyłącznie prezentacja i polecenia. Bez logiki protokołu.
def print_event(event: Event, json_output: bool = False):
    if json_output:
        print(json.dumps(event.to_dict(), ensure_ascii=False), flush=True)
        return
    stamp = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
    name = event.module.value + (f"/{event.serial}" if event.serial else "")
    if event.action == "raw":
        description = f"RAW {event.raw.hex(' ')} {event.message}"
    elif event.action == "slider_changed":
        description = f"S{event.control}: POZYCJA {event.value}/100"
    elif event.action in ("pressed", "released", "rotated"):
        action = {"pressed": "WCIŚNIĘCIE", "released": "PUSZCZENIE",
                  "rotated": "OBRÓT"}[event.action]
        direction = {"left": "LEWO", "right": "PRAWO"}.get(event.direction, "")
        description = f"{event.control}: {action} {direction}"
    else:
        description = f"{event.action}: {event.message}"
    print(f"{stamp} [{name}] {description.rstrip()}", flush=True)


CONSOLE_HELP = """Polecenia konsoli (ścieżki ze spacjami ujmij w cudzysłów):
  devices                    lista uruchomionych modułów
  key 1 obraz.png             grafika na klawisz 1..15
  dial obraz.png              grafika na gałkę IPS
  key 1 obraz.png SERIAL      wybór egzemplarza 15-Key
  dial obraz.png SERIAL       wybór egzemplarza Dial
  reconnect                  zamknij i ponownie wykryj urządzenia USB
  help                       ta pomoc
  quit                       zakończ; działa także Ctrl+C
"""


def show_devices(infos: list[DeviceInfo]):
    if not infos:
        print("Brak dostępnych obsługiwanych modułów.", flush=True)
    for info in infos:
        print(f"{info.module.value}: {info.name}, serial={info.serial or '-'}, "
              f"PID={info.pid:04X}", flush=True)


def console_command(hub: MasterHub, line: str) -> bool:
    parts = shlex.split(line)
    if not parts:
        return True
    command, *args = parts
    if command in ("quit", "exit"):
        return False
    if command == "help" and not args:
        print(CONSOLE_HELP, flush=True)
    elif command == "devices" and not args:
        show_devices(hub.devices())
    elif command == "reconnect" and not args:
        show_devices(hub.restart())
    elif command == "key" and len(args) in (2, 3):
        hub.set_key_image(int(args[0]), args[1], serial=args[2] if len(args) == 3 else None)
        # Wynik wróci przez Event image_sent/error, bez blokowania konsoli.
    elif command == "dial" and len(args) in (1, 2):
        hub.set_dial_image(args[0], serial=args[1] if len(args) == 2 else None)
    else:
        raise ValueError("Nieznane polecenie lub argumenty. Wpisz help.")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="MasterHUB: rdzeń HID i konsola")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("list", help="Lista urządzeń bez otwierania HID")
    run = commands.add_parser("run", help="Zdarzenia i polecenia obrazów w jednej konsoli")
    run.add_argument("--raw", action="store_true")
    monitor = commands.add_parser("monitor", help="Sam monitor zdarzeń, Ctrl+C kończy")
    monitor.add_argument("--raw", action="store_true")
    monitor.add_argument("--json", action="store_true", help="Zdarzenia jako JSON Lines")
    monitor.add_argument("--seconds", type=float, help="Zakończ po określonym czasie")
    for name, description in (("key", "Grafika na klawisz 1..15"), ("dial", "Grafika na gałkę IPS")):
        p = commands.add_parser(name, help=description)
        if name == "key":
            p.add_argument("number", type=int)
        p.add_argument("image", type=Path)
        p.add_argument("--serial")
        p.add_argument("--quality", type=int)
        p.add_argument("--dry-run", action="store_true", help="Przygotuj pakiety bez HID")
    args = parser.parse_args()
    command = args.command or "run"
    if getattr(args, "seconds", None) is not None and args.seconds <= 0:
        parser.error("--seconds musi być dodatnie")
    if command == "key" and not 1 <= args.number <= 15:
        parser.error("Numer klawisza musi wynosić 1..15")
    if command in ("key", "dial") and args.dry_run:
        spec = SPECS[0x01FE if command == "key" else 0x0206]
        jpeg = prepare_image(args.image, spec, args.quality)
        packets = list(image_reports(jpeg, spec, args.number if command == "key" else 1))
        print(f"JPEG {spec.image_size}: {len(jpeg)} B; {len(packets)} raportów po 320 B")
        print("Pierwszy nagłówek:", packets[0][:8].hex(" "))
        print("Ostatni nagłówek: ", packets[-1][:8].hex(" "))
        print("Bez otwierania HID i bez zapisu do urządzenia.")
        return 0
    modules = [Module.KEYS] if command == "key" else [Module.DIAL] if command == "dial" else None
    hub = MasterHub(modules, raw=getattr(args, "raw", False))
    if command == "list":
        show_devices(hub.discover())
        return 0
    try:
        infos = hub.start()
        if not infos and command != "run":
            raise RuntimeError("Nie znaleziono obsługiwanych modułów")
        if command in ("key", "dial"):
            future = (hub.set_key_image(args.number, args.image, serial=args.serial, quality=args.quality)
                      if command == "key" else hub.set_dial_image(args.image, serial=args.serial, quality=args.quality))
            result = future.result(timeout=30)
            print(f"HIDAPI przyjęło obraz: {result.jpeg_bytes} B, {result.reports} raportów. "
                  "Sprawdź grafikę na urządzeniu.")
            return 0
        lines: queue.Queue[str | None] = queue.Queue()
        if command == "run":
            print("MasterHUB — konsola. Zdarzenia pojawiają się na bieżąco.")
            print(CONSOLE_HELP, flush=True)

            def read_stdin():
                for line in sys.stdin:
                    lines.put(line)
                lines.put(None)  # EOF kończy konsolę; monitor nie czyta stdin

            threading.Thread(target=read_stdin, name="terminal-input", daemon=True).start()
        started = time.monotonic()
        while True:
            try:
                event = hub.get_event(timeout=0.1)
                print_event(event, getattr(args, "json", False))
            except queue.Empty:
                pass
            for event in hub.get_events():
                print_event(event, getattr(args, "json", False))
            if command == "run":
                try:
                    line = lines.get_nowait()
                except queue.Empty:
                    continue
                if line is None:
                    break
                try:
                    if not console_command(hub, line):
                        break
                except (ValueError, RuntimeError, OSError) as error:
                    print(f"BŁĄD polecenia: {error}", flush=True)
            if command == "monitor":
                if args.seconds is not None and time.monotonic() - started >= args.seconds:
                    break
                if infos and not hub.devices():
                    return 1
    except KeyboardInterrupt:
        if not getattr(args, "json", False):
            print("\nZatrzymywanie…", flush=True)
    finally:
        hub.stop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, ImportError, TimeoutError) as error:
        print(f"BŁĄD: {error}", file=sys.stderr)
        sys.exit(1)
