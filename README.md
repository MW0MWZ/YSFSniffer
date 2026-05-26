# YSFSniffer

A passive logger for the **air side** of the Yaesu System Fusion (YSF) protocol
as it appears on the UDP link between MMDVM Host and a YSF Gateway. Its only
job is to write detailed, annotated dumps of every frame so you can reverse
engineer the protocol off-line.

It is **not** a gateway. It never transmits anything. It does not connect to
reflectors. It does not handle Wires-X commands. It does not bridge MMDVM Host
to anything. If you want a working gateway, run
[YSFGateway](https://github.com/g4klx/YSFClients).

## Scope

YSFSniffer captures and decodes what travels over UDP between MMDVM Host and
its configured YSF network client — that is, the same byte stream that was on
RF a moment earlier (or is about to be). It is **strictly for the on-air YSF
protocol**.

It does **not** look at the closed Yaesu Wires-X reflector network. That is a
completely different problem and is investigated separately via packet
captures.

## Build

Everything happens inside a Docker container so nothing leaks onto the host.

```sh
# Build the toolchain image once
make image

# Build the sniffer binary
make docker-build

# Optional: drop into a shell inside the build container
make docker-shell

# Clean build artefacts
make docker-clean
```

The resulting `YSFSniffer` binary lands in the project root.

## Running it

YSFSniffer reuses an existing **YSFGateway** `.ini` file — it reads
`[General] LocalAddress`, `LocalPort`, `RptAddress`, `RptPort`, and `Callsign`,
plus an optional `[Sniffer]` section for sniffer-specific knobs.

```sh
./YSFSniffer /etc/YSFGateway.ini > capture.log
```

### Important: stop YSFGateway first

YSFSniffer binds to the same UDP port that YSFGateway uses to receive frames
from MMDVM Host. Only one process can hold that port at a time.

Either:

- stop YSFGateway while you're sniffing, or
- temporarily point MMDVM Host's `[System Fusion Network]` settings at a
  different host/port and run YSFSniffer there.

When the sniffer is running, MMDVM Host's YSF traffic will be **logged but not
forwarded** to any reflector. This is intentional — passive only.

### Optional `[Sniffer]` section

Add this to your `.ini` to tune output:

```ini
[Sniffer]
OutputFile=
Stdout=1
DecodeFICH=1
OnlyYSFD=0
FilterByRpt=0
```

| Key            | Default | Meaning                                                                                  |
|----------------|---------|------------------------------------------------------------------------------------------|
| `OutputFile`   | (none)  | If set, write the log here (append). Empty = stdout only.                                |
| `Stdout`       | `1`     | Also keep stdout flowing when an `OutputFile` is set.                                    |
| `DecodeFICH`   | `1`     | Run the full FICH Viterbi/Golay/CRC decode on each frame.                                |
| `OnlyYSFD`     | `0`     | Drop everything that isn't a `YSFD` data frame.                                          |
| `FilterByRpt`  | `0`     | Only accept packets whose source IP matches `[General] RptAddress`.                      |

## Licence

GPL v2 — see `LICENCE`. The borrowed protocol files (`YSFFICH`,
`YSFConvolution`, `Golay24128`, `CRC`, `YSFDefines.h`) are unmodified GPL v2
code from G4KLX's [YSFClients](https://github.com/g4klx/YSFClients) project
and retain his copyright headers.
