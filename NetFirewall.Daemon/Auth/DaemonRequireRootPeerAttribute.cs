namespace NetFirewall.Daemon.Auth;

/// <summary>
/// Endpoint metadata: only accept requests whose Unix-socket peer UID is 0 (root).
/// Used by the recovery endpoints, which must stay reachable when the session path is
/// blocked (locked-out admin, lost TOTP) — they bypass <c>X-NetFw-Session</c> and rely on
/// root on the box as the sole credential.
///
/// <para>Enforced by <see cref="DaemonEndpointGateMiddleware"/>. It is a plain marker, not
/// an MVC filter: minimal APIs never run MVC filters, which is how this gate used to be
/// silently ignored. Independent of <see cref="PeerCredentialMiddleware"/> (the socket-wide
/// allow-list) — both must pass.</para>
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class DaemonRequireRootPeerAttribute : Attribute;
