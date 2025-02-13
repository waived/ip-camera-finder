  ////////////////////////
 /// IP CAMERA FINDER ///
////////////////////////

About: this script aims to expose IP Camera/Doorbell feeds that use common
       streaming ports and protocols.

Supported protocols:
    [+] HTTP/s
    [+] RTSP
    [+] RTMP

Protocols: the HTTP protocol is scanned on 80, 443, and 8443. As for RTSP,
       port 554 is scanned, and RTMP 1935. Other less common ports are
       scanned such as port 37777. There are certainly more. 8000, 8008,
       8080, 9000, 52221, etc. These can easily be added at the will of
       the user.

Responses:
       When successful HTTP-GET requests are delivered ("200 OK" from server)
       using either 80, 443, and 8443, the HTTP Headers and HTML code is inspected
       for certain HTML tags and plain-text keywords commonly used in camera/video
       feeds. As for RTSP and RTMP, specific requests/handshakes are customized
       and sent to determine if indeed said service is broadcast video frames and
       audio for a camera. This helps weed out and false-positives when sending
       each probe.

Probe: this script uses TCP-SYN probes for each port. This is done in effort
       not to exhaust client-side sockets by initializing a complete socket.
       If a SYN-ACK response is received, then the protocol/port is fully
       investigated. This operation works as a basic SYN-scanner to conserve
       resources and to keep traffic to a bare-minimum.

Host generation:
       Each endpoint IP-Address that is generated is done specifically to avoid
       any/all IP ranges that are either reserved for internal traffic, link-local,
       or broadcast traffic. Excluding these will heavyily reduce false-positive
       detections and keep a load off of the internal LAN.
