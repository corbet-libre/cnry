# Small devices (ESP32 and similar)

Design note, no code yet.

## Flow

1. Connect to Wi-Fi and the MQTT broker (TLS) and subscribe to the retained
   topic `public/canary/<system>`. The retained message arrives immediately
   after subscribing; later renewals replace it.
2. Get the time from NTP. **No valid time means absent**: without a clock
   `expires` cannot be checked.
3. Verify locally exactly as in `spec.md`: parse the JSON, compare the `key`
   fingerprint with the pinned public key stored in firmware, canonicalise
   (RFC 8785, strings and integers only), check the Ed25519 signature, then
   `issued`, `expires` and the freshness rules.
4. Show the result: present or absent. Re-check against the clock at least
   once a minute, and whenever a message arrives; a device that loses the
   broker keeps its last verified statement until `expires`, then shows
   absent. A broker that never delivers a message leaves the device absent.

## Output

| Hardware | Present | Absent |
|---|---|---|
| One LED | on | off |
| Small screen | the sprite from `src/scene.rs` (24 x 18 pixels, nine palette letters) on the swing, optionally swinging a few degrees | the empty swing at rest |

The sprite and palette are plain data; a device can embed the 18 rows as a
bitmap. A 128 x 64 monochrome screen can draw the bird as a silhouette.

## Constraints

* Ed25519 verification is available in mbedTLS/libsodium/Monocypher builds
  that fit an ESP32; SHA-256 for the fingerprint likewise. No signing on the
  device, ever.
* The pinned key is compiled in or stored in a write-protected partition; a
  device must not accept a key from the network.
* The firmware must not renew or extend anything: it only displays.
