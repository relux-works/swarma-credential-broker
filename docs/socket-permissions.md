# Socket permissions in the v0 profile

The listener uses the socket mode **0666** specified by
[broker deployment paths](../spec/broker.md#152-paths). Filesystem access lets a
peer connect; Linux `SO_PEERCRED` supplies its UID, and the static per-account
allowlist controls admission. An unlisted peer receives the terminal refusal
before the server reads a request. The socket grants no authority by itself.

The operator must create a separate socket directory before startup. Its owner
must be the daemon's effective UID and its mode must be exactly **0755**. The
listener refuses a missing directory, links, a different owner, extra mode bits,
or a different mode. It never repairs directory permissions or adopts an
existing socket-path entry. It sets and verifies the owned socket's mode and
rechecks the directory and socket mode when serving starts. These are startup
checks, not continuous detection of later filesystem changes.

## Ancestors under interim R2

The current listener implements the profile's accepted same-user R2 boundary:
paths must be absolute and clean, every directory component must be a real
directory, and every ancestor must belong to root or the daemon's UID. Ancestors
must not be writable by group or others. A root-owned sticky directory is the
exception: its sticky bit protects the already-existing owned child from
replacement by other UIDs. This permits qualification beneath a temporary
filesystem without changing shared directory permissions. The socket directory
itself still requires exactly 0755, without the sticky bit.

These checks do not establish the dedicated service deployment's stronger
requirement that **every ancestor be root-owned and not writable by others**.
In R2 the daemon's own UID can replace its directories, socket or executable;
same-UID hostile processes and root are outside that isolation guarantee.
A protected ancestor can also prevent otherwise allowed peers from traversing
the path: cross-UID reachability must be qualified with the intended installation
permissions. A dedicated deployment must supply the stricter root-owned ancestor
chain in the deployment table; a passing temporary fixture does not qualify it.

## Genuine peer qualification

Follow the README's standalone `peeraccounts` build and protected configuration.
Install a copy of that exact binary in a path traversable by both configured
peer accounts, mode 0555. Provision a daemon-owned mode-0755 socket directory
with traversable ancestors; retain the mode-0600 configuration privately.
`TestConfiguredPeers` covers terminal denial without client writes, allowed
hello and leasing, and a separately admitted foreign UID's ownership refusal.
`TestConfiguredPeerConnect` separately tests cross-UID connect and server-UID
verification without protocol I/O. Restoring socket mode 0600 must fail this
connection test. Neither test creates accounts or adjusts shared permissions.
Remove only the qualification's own fixtures and recorded process tree.
