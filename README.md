ZTOR
===
Zig BitTorrent Client
---

A small but slightly more than non-trivial program written in Zig.

This was mostly an experiment in using zig with a c event-loop library and callback-based appraoch. A number of
useful zig features, such as errors, can't be used due to the C abi boundary being pervasive.

I do not recommend using this code as a good example as there are no tests and currently I've thrown a lot of it together in one place. But if it helps then go for it.

The torrent file is for the [debian net install image](https://cdimage.debian.org/debian-cd/current/amd64/bt-cd/) which was used because 
    A. debian has seeders so we probably don't have to worry about being choked all the time, and
    B. it's a single file torrent so no need to deal with directories and multiple files.

### Build

This program depends on a number of modules and builds both http\_parser and libuv.

```
git clone --recursive https://github.com/iansimonson/ztor.git
cd ztor
zig build
```




### Plan
- [x] Connect to tracker and download peer info
    - [x] Parse .torrent into tree
    - [x] Find announce url
    - [x] Connect and download peer list
- [x] Establish connections to peers
    - [x] Construct peer connection info per peer
    - [x] Only download on unchoke
- [ ] Use `uv_get_handle` rather than the members
- [ ] Support for N .torrent files at once
    - [ ] Don't shutdown after a file is done downloading
- [ ] Implement upload and answering requests
    - [ ] Send `have` messages to all peers on download
    - [ ] If `have` send piece on request
    - [ ] provide mechanism to get non-owning immutable slice to piece
- [ ] Setup server for incoming connections
    - [ ] Upload throttled amount of data
    - [ ] Send bitfield on new incoming connections
- [ ] Add invalid threshold
    - [ ] After x amount of invalid pieces close connection to peer
- [ ] Throttle data speeds
    - [ ] [Token Bucket](https://en.wikipedia.org/wiki/Token\_bucket)?
    - [ ] Upload throttle
    - [ ] Download throttle
- [ ] Setup imgui (or similar) for handling torrents in GUI mode

### Additional TODO:
- [ ] Build libuv in build.zig
- [ ] Move from libuv to native zig async/await
    - [ ] Abstract away libuv
- [ ] Support non-compact peer list
- [ ] Confirm peer\_ids
- [ ] Support uTP protocol rather than using TCP
- [ ] Support UDP tracker protocol (BEP 015)
- [ ] SSL/TLS support?
- [ ] Watch a folder for `.torrent` files
- [ ] Other BEPs?
- [ ] Make the Torrent Lexer work with Reader/Writer

### Relevant links
Prior to this I only knew how torrents worked conceptually. How to implement a torrent downloader was way outside what I knew. The following are relevant links when learning:

- [Building a BitTorrent client from the ground up in go](https://blog.jse.li/posts/torrent/)
- [BitTorrent protocol](https://www.bittorrent.org/beps/bep_0003.html)
- [BitTorrent.org](https://www.bittorrent.org/index.html)
- [Basics of Libuv](http://docs.libuv.org/en/v1.x/guide/basics.html)
