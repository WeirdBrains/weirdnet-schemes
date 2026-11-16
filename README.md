# weirdnet-schemes

The URL scheme registry every Weirdnet app shares, so a `weirdnet-<app>://` link means the
same thing on every device and to every app.

- **Names** ([`names`]): every app registers a prefix; its schemes are the prefix or
  `prefix-…`. Prefixes starting with `weirdnet` are reserved for WeirdBrains; first-party
  apps use `weirdnet-<app>` (`weirdnet-morph`, `weirdnet-muninn`). Standard schemes
  (`https`, `file`, `mailto`, …) can't be claimed. `weirdnet://` is internal only: never
  registered with the OS and never resolved to an app.
- **Records** ([`records`]): a [`PrefixRecord`] and a [`SchemeRecord`] (scheme, prefix,
  app id, publisher key, display name, capabilities, install hints, `seq`, expiry,
  withdrawal), each signed by the publisher's Ed25519 key over its exact JSON. Reserved
  prefixes also carry the WeirdBrains root signature and are published only on the
  **canonical list**, which the root key signs as a whole. A prefix moves to a new publisher
  only with a transfer signature from the previous one; the root key rotates by a record
  both the old and the new key sign.
- **Resolver** ([`Registry`]): takes the canonical list, records from relays (and later the
  DHT) and installed apps; refuses unsigned, stale, expired and withdrawn records and any
  `weirdnet…` claim outside the list. Resolution prefers the user's pin, then the canonical
  list, then an installed app whose publisher matches, and otherwise returns
  [`Resolution::Choose`] so the app asks the user. It never picks a stranger's record on
  its own. The registry serializes as the device's local cache.
- **Links** ([`Link`]): `<scheme>://join/<code>`, `<scheme>://answer/<code>`, and
  `<scheme>://<name or user id>/<path>` for resources held by peers.
- **Install hints**: Salty Gull, App Store, Google Play, F-Droid or an HTTPS page, filtered
  by [`Platform`]. They are shown, never acted on without the user.
- **OS registration** ([`os`]): the Linux `.desktop` entry and `xdg-mime` defaults, the
  per-user Windows registry keys (or a `.reg` file), `CFBundleURLTypes` for macOS and iOS,
  and the Android intent filter, for an app's own schemes. All of them refuse
  `weirdnet://`.

The WeirdBrains root key is held by m3talsmith and used through
[`weirdnetctl`](https://github.com/WeirdBrains/weirdnetctl), which signs the reserved
prefixes and the canonical list; apps ship its public key as their trust anchor.

BSD-3-Clause.
