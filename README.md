# MasterHUB for macOS

An unofficial Python implementation of Cooler Master MasterHUB support on macOS, using HIDAPI.

The project provides a terminal interface and a reusable core for future GUI development.

## Supported modules

| Module | Supported features |
|---|---|
| 15-Key IPS | Button presses and individual key images |
| Dial IPS (M131E) | Left/right rotation, press/release events, and screen images |
| 3x Knob | Left/right rotation and press events for each knob |
| 5x Slider | Position updates for all five sliders, ranging from 0 to 100 |

The dual roller module is currently unsupported.

## Features

- JPEG image transfer: 72×72 for LCD keys and 240×240 for the IPS dial.
- Live button, encoder, and slider events.
- Image uploads while monitoring events in the same terminal session.
- Background HID workers and queued image transfers.
- A shared event API for future GUI integration.
- Raw HID diagnostics and JSON event output.

## Installation

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install hidapi Pillow
```

## Usage

Start the interactive console:

```bash
python masterhub_core.py
```

Upload images from the running console:

```text
key 1 image.png
dial image.png
```

Other console commands:

```text
devices
reconnect
help
quit
```

Standalone commands:

```bash
python masterhub_core.py list
python masterhub_core.py monitor
python masterhub_core.py monitor --raw
python masterhub_core.py monitor --json
python masterhub_core.py key 1 image.png
python masterhub_core.py dial image.png
```

## Development

`masterhub_core.py` contains the HID protocol, event decoding, image preparation, device workers, public API, and terminal interface.

Applications can import `MasterHub`, receive events through its queue, and submit image transfers asynchronously.

The implementation is based on working device tests and static analysis of the SDK distributed with MasterHUB. Image packet compatibility and core behavior have been checked through offline tests. Hardware reports have confirmed dial events and slider positions.

## Current limitations

- Dual roller support remains unresolved.
- USB reconnection is manual through `reconnect`.
- Brightness control and firmware updates are not implemented.
- Hardware and firmware compatibility may vary.

This is an independent community project and is not affiliated with Cooler Master.
