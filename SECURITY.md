# Security

Report problems privately to m3talsmith@gmail.com.

## What the registry guarantees

- Every record is signed by its publisher over its exact bytes, with the kind and the
  signature role in the signed message, so a signature can't be reused for another record
  kind or role.
- `weirdnet…` prefixes and their schemes are accepted only from a canonical list signed by
  a trusted root key, and each reserved record also carries the root signature.
- Stale (`seq` not higher), expired and withdrawn records lose; a canonical list must have a
  higher `seq` than the one held.
- A prefix changes hands only with the previous holder's transfer signature. Without it,
  two claims stand side by side and the resolver asks the user.
- Resolution never hands a link to a stranger's app without the user: pins, the canonical
  list and installed apps with a matching publisher are the only automatic choices.
- `weirdnet://` is never registered with the OS and never resolved.

## Limits

- Anyone can register a third-party prefix that nobody holds yet (first come); the
  resolver's conflict rule is the protection against squatting, not the registration.
- Trust in first-party schemes is trust in the root key; rotate it with `weirdnetctl` if
  it is ever exposed, and ship the new anchor in app updates.
