namespace NetFirewall.Daemon.Auth;

/// <summary>
/// Marker that documents an endpoint as eligible for the root-peer principal installed
/// pipeline-wide by <see cref="RootPeerBypassMiddleware"/> (boot-time apply, root tools).
/// Carries no logic: the bypass happens in that middleware, before authorization.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class DaemonAllowRootPeerAttribute : Attribute;
