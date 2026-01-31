# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetFirewall is a personal firewall system built with C# / .NET 10.0 and PostgreSQL. It uses .NET Aspire for service orchestration. The project includes a working WAN Monitor service and a DHCP Server (in progress).

## Build Commands

```bash
# Build entire solution
dotnet build

# Build for release
dotnet build -c Release

# Run tests
dotnet test

# Run a single test
dotnet test --filter "FullyQualifiedName~TestMethodName"

# Run development (via Aspire AppHost)
dotnet run --project NetFirewall.AppHost

# Publish WAN Monitor for Linux deployment
dotnet publish -c Release -r linux-x64 -o /opt/netfirewall/wanmonitor NetFirewall.WanMonitor

# Publish DHCP Server for Linux deployment
dotnet publish -c Release -r linux-x64 -o /opt/netfirewall/dhcpserver NetFirewall.DhcpServer
```

## Architecture

### Service Projects

- **NetFirewall.AppHost**: .NET Aspire orchestration layer - coordinates all services for development
- **NetFirewall.WanMonitor**: Background worker that monitors dual WAN interfaces with automatic failover/failback. Executes configurable bash commands on network state changes
- **NetFirewall.DhcpServer**: RFC 2131 compliant DHCP server with PXE boot support. Uses UDP port 67 (requires root). Stores leases in PostgreSQL
- **NetFirewall.Web**: Blazor Server web interface with Tailwind CSS 4.x for styling
- **NetFirewall.ApiService**: REST API (Minimal APIs with OpenAPI)

### Shared Libraries

- **NetFirewall.Models**: Data models for:
  - DHCP: DhcpConfig, DhcpRequest, DhcpResponse, DhcpLease, DhcpMacReservation, DhcpOption
  - WAN Monitor: NetworkInterfaceConfig, BashCommandsConfig
  - Firewall: FwInterface, FwPortForward, FwFilterRule, FwNatRule, FwMangleRule, FwTrafficMark, FwQosConfig, FwQosClass, FwAuditLog
- **NetFirewall.Services**: Business logic and data access via RepoDb ORM. Key services: DhcpServerService, DhcpLeasesService
- **NetFirewall.ServiceDefaults**: Aspire shared configuration (OpenTelemetry, service discovery, resilience)

### Database

PostgreSQL database `net_firewall` with tables:

**DHCP Tables:**
- `dhcp_config`: Server configuration (IP ranges, lease time, DNS servers, boot options)
- `dhcp_leases`: Active IP assignments (MAC address, IP, hostname, timestamps)
- `dhcp_mac_reservations`: Static IP reservations

**Firewall Tables:**
- `fw_interfaces`: Network interface definitions (WAN, LAN, VPN)
- `fw_port_forwards`: DNAT port forwarding rules
- `fw_filter_rules`: Input/Forward/Output filter rules
- `fw_nat_rules`: SNAT/Masquerade rules
- `fw_mangle_rules`: Traffic marking rules for QoS/routing
- `fw_traffic_marks`: Traffic mark definitions for policy routing
- `fw_qos_config`: QoS configuration per interface
- `fw_qos_classes`: HTB class definitions for QoS
- `fw_audit_log`: Audit trail for configuration changes

Schema located in `NetFirewall.Services/sql/Schema.sql`

## Key Implementation Details

- **DHCP packet processing**: Uses TPL Dataflow (BufferBlock) for async packet handling in `DhcpWorker`
- **DHCP lease management**: Uses NpgsqlDataSource for connection pooling, parameterized queries to prevent SQL injection, and database transactions to prevent race conditions
- **WAN failover logic**: `WanMonitorService` pings configurable IPs through each interface, switches routes on failure
- **Logging**: Serilog with console + rolling file output to `/logs/` directory
- **Configuration**: Each service has its own `appsettings.json` for interface configs, IP ranges, connection strings

## UI Stack

- **Blazor Server**: Interactive server-side rendering
- **Tailwind CSS 4.x**: Utility-first CSS framework for styling

## Bash Scripts

The `/Bash/` directory contains production firewall scripts (`firewall.sh`, `nftables.conf`) that the WAN Monitor integrates with via configurable bash commands.
