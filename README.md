# Ongaku
Efficient network audio server/client written in C

## Requirements
- libpulse (Linux)
- libportaudio (Windows and macOS)
- libsodium
- libopus

## Compiling
Compilation is done using Meson.

```
meson setup builddir
cd builddir
meson test
meson compile
meson install
```

## Running

### Server
```
ongaku-server
```

### Client
```
ongaku-client 192.168.0.1
```
