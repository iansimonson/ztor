ZTOR
===
Zig BitTorrent Client
---

### Plan
- [ ] Connect to tracker and download peer info
    - [ ] Parse .torrent into tree
    - [ ] Find announce url
    - [ ] Connect and download peer list
- [ ] Establish connections to peers
    - [ ] Construct peer connection info per peer
    - [ ] Only download on unchoke
- [ ] Setup server for incoming connections
    - [ ] Upload throttled amount of data
- [ ] Throttle data speeds
    - [ ] [Token Bucket](https://en.wikipedia.org/wiki/Token_bucket)?
        - Basically a rolling window
    - [ ] Upload throttle
    - [ ] Download throttle
- [ ] Setup imgui for handling torrents in GUI mode

### Additional TODO:
- [ ] Support non-compact peer list
- [ ] Confirm peer_ids
- [ ] Support uTP protocol rather than using TCP
- [ ] SSL/TLS support?