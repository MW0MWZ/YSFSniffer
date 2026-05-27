# YSFSniffer

A passive, log-only fork of [g4klx/YSFClients](https://github.com/g4klx/YSFClients)'
`YSFGateway`. It speaks to MMDVMHost exactly the same way YSFGateway does — same
INI file, same UDP link — but its only job is to write every received frame to
the log via the existing `CUtils::dump()` path that `Debug=1` already provides.

No reflectors. No FCS. No Wires-X command processing. No APRS. No GPS. No MQTT.
Never transmits anything back to MMDVMHost.

Intended as a reverse-engineering aid for the on-air YSF protocol — every byte
MMDVMHost punts at it gets logged so you can analyse it off-line.

## Build

All compilation happens inside the Docker toolchain image so the host stays
clean. The output binary is a normal Linux ELF you copy to the target box.

```sh
# build the toolchain image once
make image

# native build (build-host arch, useful for sanity checks)
make docker-build

# Raspberry Pi targets
make docker-build-arm64   # Pi 3/4/5 64-bit, WPSD
make docker-build-armhf   # 32-bit Pi, Pi-Star

make docker-clean
```

The binaries land in the project root as `YSFSniffer`, `YSFSniffer-arm64`,
`YSFSniffer-armhf`.

## Run

Copy the appropriate binary to the box that runs MMDVMHost + YSFGateway and
run it in place of YSFGateway, pointing at the **same** `YSFGateway.ini` your
gateway already uses:

```sh
sudo systemctl stop ysfgateway
./YSFSniffer-arm64 /etc/YSFGateway.ini
# ... do your testing ...
sudo systemctl start ysfgateway
```

YSFSniffer reads the same `[General]` keys as YSFGateway (callsign, local /
RptAddress, ports, daemon, etc.) and the same `[Log]` keys (`FilePath`,
`FileRoot`, `FileLevel`, `DisplayLevel`, `FileRotate`) — so whatever rotating
log file your existing YSFGateway writes to, YSFSniffer writes to too. No
config edits required. MMDVMHost does not need to be touched.

While YSFSniffer is running it logs every frame received from MMDVMHost but
forwards nothing anywhere — your radio's YSF traffic will not reach a reflector
during the capture session.

## Licence

GPL v2 — see `LICENCE`. All borrowed sources from `g4klx/YSFClients` retain
their original copyright headers.
