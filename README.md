ZTOR
===
Zig BitTorrent Client
---

A small-ish but non-trivial program for seeing where zig breaks down / shines.

### Plan
- [x] Connect to tracker and download peer info
    - [x] Parse .torrent into tree
    - [x] Find announce url
    - [x] Connect and download peer list
- [ ] Establish connections to peers
    - [x] Construct peer connection info per peer
    - [ ] Only download on unchoke
- [ ] Use `uv_get_handle` rather than the members
- [ ] Setup server for incoming connections
    - [ ] Upload throttled amount of data
- [ ] Throttle data speeds
    - [ ] [Token Bucket](https://en.wikipedia.org/wiki/Token\_bucket)?
    - [ ] Upload throttle
    - [ ] Download throttle
- [ ] Setup imgui for handling torrents in GUI mode
- [ ] Support for N .torrent files at once

### Additional TODO:
- [ ] Move from libuv to native zig async/await
    - [ ] Abstract away libuv
- [ ] Support non-compact peer list
- [ ] Confirm peer_ids
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
