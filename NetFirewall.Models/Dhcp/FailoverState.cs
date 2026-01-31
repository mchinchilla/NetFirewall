namespace NetFirewall.Models.Dhcp;

/// <summary>
/// DHCP Failover protocol states (ISC-DHCP / draft-ietf-dhc-failover-12)
/// </summary>
public enum FailoverState
{
    /// <summary>
    /// Initial state before communication established
    /// </summary>
    Startup = 0,

    /// <summary>
    /// Normal operation, both peers communicating
    /// </summary>
    Normal = 1,

    /// <summary>
    /// Lost contact with peer, waiting before taking action
    /// </summary>
    CommunicationsInterrupted = 2,

    /// <summary>
    /// Peer is confirmed down, taking over all addresses
    /// </summary>
    PartnerDown = 3,

    /// <summary>
    /// Potential conflict detected, needs resolution
    /// </summary>
    PotentialConflict = 4,

    /// <summary>
    /// Recovering from partner-down or conflict state
    /// </summary>
    Recover = 5,

    /// <summary>
    /// Paused state during recovery
    /// </summary>
    Paused = 6,

    /// <summary>
    /// Shutting down gracefully
    /// </summary>
    Shutdown = 7,

    /// <summary>
    /// Waiting for peer to recover
    /// </summary>
    RecoverWait = 8,

    /// <summary>
    /// Done recovering, transitioning to normal
    /// </summary>
    RecoverDone = 9,

    /// <summary>
    /// Resolving binding conflicts
    /// </summary>
    ResolutionInterrupted = 10,

    /// <summary>
    /// Conflict resolution complete
    /// </summary>
    ConflictDone = 11
}

/// <summary>
/// Failover message types
/// </summary>
public enum FailoverMessageType : byte
{
    /// <summary>
    /// Request pool allocation info
    /// </summary>
    PoolReq = 1,

    /// <summary>
    /// Response to pool request
    /// </summary>
    PoolResp = 2,

    /// <summary>
    /// Binding update (lease change notification)
    /// </summary>
    BndUpd = 3,

    /// <summary>
    /// Binding update acknowledgment
    /// </summary>
    BndAck = 4,

    /// <summary>
    /// Connect request
    /// </summary>
    Connect = 5,

    /// <summary>
    /// Connect acknowledgment
    /// </summary>
    ConnectAck = 6,

    /// <summary>
    /// Request all updates since timestamp
    /// </summary>
    UpdReqAll = 7,

    /// <summary>
    /// Request missed updates
    /// </summary>
    UpdReq = 8,

    /// <summary>
    /// Update complete notification
    /// </summary>
    UpdDone = 9,

    /// <summary>
    /// State change notification
    /// </summary>
    State = 10,

    /// <summary>
    /// Contact/keepalive message
    /// </summary>
    Contact = 11,

    /// <summary>
    /// Disconnect notification
    /// </summary>
    Disconnect = 12
}

/// <summary>
/// Failover binding states for leases
/// </summary>
public enum FailoverBindingState : byte
{
    /// <summary>
    /// Address is free and available
    /// </summary>
    Free = 0,

    /// <summary>
    /// Address is actively leased
    /// </summary>
    Active = 1,

    /// <summary>
    /// Lease expired, in grace period
    /// </summary>
    Expired = 2,

    /// <summary>
    /// Lease released by client
    /// </summary>
    Released = 3,

    /// <summary>
    /// Address abandoned (conflict detected)
    /// </summary>
    Abandoned = 4,

    /// <summary>
    /// Address reset by administrator
    /// </summary>
    Reset = 5,

    /// <summary>
    /// Backup address (owned by secondary)
    /// </summary>
    Backup = 6,

    /// <summary>
    /// Reserved but not yet leased
    /// </summary>
    Reserved = 7
}

/// <summary>
/// Failover peer role
/// </summary>
public enum FailoverRole
{
    Primary,
    Secondary
}

/// <summary>
/// Reject reasons for failover operations
/// </summary>
public enum FailoverRejectReason : byte
{
    None = 0,
    UnknownReason = 1,
    IllegalIpAddress = 2,
    PartNotOwner = 3,
    ConflictingUpdate = 4,
    MissingBindingInfo = 5,
    ConnectionRejected = 6,
    TimeoutRejected = 7,
    InvalidMclt = 8,
    MismatchedProtocol = 9,
    OutdatedBindingInfo = 20,
    LessCriticalBindingInfo = 21,
    NoAnswer = 254,
    Unknown = 255
}
