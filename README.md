# NetFirewall

> Desde hace algun tiempo habia tenido la idea de hacer mi propio firewall para mi casa, he usado muchos buenos productos entre ellos, pfsense, opnsense, ipcop, zenthyal, clearos, vyos, ipfire, endian, todos con sus pro y contras.
Para este 2025 he dicidido poner en marcha el desarrollo de mi propio firewall, hecho desde cero utilizando C# (y todo el ecosistema de dotnet) y como base de datos Postgresql.
En esta primera etapa, estaré desarrollando el DHCP.
Si te interesa colaborar con este proyecto desde ya eres bienvenido.

> For some time I had the idea of making my own firewall for my home, I have used many good products including pfsense, opnsense, ipcop, zenthyal, clearos, vyos, ipfire, all with their pros and cons.
For this 2025 I have decided to start developing my own firewall, made from scratch using C# (and the entire dotnet ecosystem) and Postgresql as a database.
In this first stage, I will be developing the DHCP.
If you are interested in collaborating with this project, you are welcome.

---

> En el directorio raiz he agregado un directorio llamado Bash, en el cual pueden encontrar el firewall que ya está funcionando en mi casa y el cual es la meta a crear a partir de un WebUI e interactuar con el core y/o bash del servidor.
El WanMonitor esta funcionando perfectamente el Dhcp Server es un trabajo en progreso aun.
 
> In the root directory I have added a directory called Bash, in which you can find the firewall that is already running at my house and which is the goal to create from a WebUI and interact with the core and/or bash of the server.
The WanMonitor is working perfectly and the Dhcp Server is still a work in progress.
---

# DHCP Server [ In Progress ... ]
RFC 2131 outlines the Dynamic Host Configuration Protocol (DHCP), which is used by hosts to obtain network configuration parameters like IP addresses, subnet masks, default gateways, and DNS servers. Here's how the dialog between a DHCP client and server generally unfolds according to RFC 2131:
### 1. DHCPDISCOVER
Client Action: When a client (like a new device on the network) wants to join the network, it broadcasts a DHCPDISCOVER message. This is sent to the local subnet's broadcast address (255.255.255.255) or to the limited broadcast address (0.0.0.0) if the client doesn't have an IP yet.
Packet Details:
Message Type: Option 53 set to Discover (1).
Client Identifier: Option 61, often the client's MAC address, for uniquely identifying the client.
Parameter Request List: Option 55, listing which options the client wants from the server.

### 2. DHCPOFFER
Server Action: Multiple DHCP servers might respond to the DISCOVER message. Each server that can offer an IP address will send back a DHCPOFFER message.
Packet Details:
Message Type: Option 53 set to Offer (2).
Your (client) IP address (YiAddr): The IP address being offered.
Server Identifier: Option 54, the server's IP address.
Subnet Mask, Router, DNS Servers, Lease Time, etc., are included as options.

### 3. DHCPREQUEST
Client Action: After receiving one or more offers, the client selects one and sends a DHCPREQUEST to the chosen server. This message can be broadcast or unicast depending on whether the client knows the server's address:
If broadcast, it informs all servers of the selection.
If unicast, it's directly to the chosen server.
Packet Details:
Message Type: Option 53 set to Request (3).
Server Identifier: Identifies which server's offer was accepted.
Requested IP Address: Option 50, the IP address the client wants (from an offer).
If this is a renewal or rebinding, different server identifiers might be used based on the client's state.

### 4. DHCPACK
Server Action: The server that offered the selected IP address responds with DHCPACK (Acknowledgment) if the IP is still available.
Packet Details:
Message Type: Option 53 set to Ack (5).
YiAddr: Confirms the IP address assignment.
Server Identifier: Option 54, reaffirming the server's identity.
Lease Time, Renewal (T1), Rebinding (T2) Times: Option 51, 58, and 59 respectively, setting the lease terms.

### 5. DHCPNAK
Server Action: If the requested IP address is no longer available or not valid, the server responds with DHCPNAK (Negative Acknowledgment).
Packet Details:
Message Type: Option 53 set to Nak (6).

Additional Messages:
### DHCPDECLINE:
If a client detects that the IP address offered is already in use, it sends DHCPDECLINE to inform the server to not re-offer that IP.
### DHCPRELEASE:
When a client no longer requires the IP address, it sends DHCPRELEASE to the server, which then frees up that IP for others.
### DHCPINFORM:
Clients with statically assigned addresses can use this to request just configuration parameters like DNS servers without asking for an IP address.

### Lease Management:
Renewal: Clients attempt to renew their lease when T1 time has passed, sending a DHCPREQUEST directly to the server that issued the lease.
Rebinding: If renewal fails, at T2, clients broadcast DHCPREQUEST messages to any DHCP server to try and extend their lease.

### Considerations:
Timers: DHCP uses timers like T1 (renewal) and T2 (rebind) to manage lease lifecycle.
Broadcast vs. Unicast: Early messages are broadcast, but after an IP is assigned, unicast communication can occur for efficiency.
Relay Agents: In networks with multiple subnets, DHCP relay agents can be used to forward requests between subnets.

This interaction ensures that clients can dynamically acquire network configurations in a standardized manner, enhancing network manageability and client mobility.

---

# NetFirewall.WanMonitor
> Esta pequeña aplicación monitorea la conexión a internet de cada interface WAN, si la conexión se pierde en la interface WAN primaria hace el cambio a la secundaria y viceversa.
---
> This small application monitors the internet connection of each WAN interface, if the connection is lost on the primary WAN interface, it switches to the secondary and vice versa.

### Instrucciones básicas de implementación / Deployment Basic Instructions:
```

1. Install .NET 9.0 SDK / Runtime
2. Clone this repository
3. Open a terminal and navigate to the project folder
4. Run the following command:
   dotnet publish -c Release -r linux-x64 -o /opt/netfirewall/wanmonitor
5. Create a service file in /etc/systemd/system/netfirewall-wanmonitor.service with the following content:
[Unit]
Description=NetFirewall WAN Monitor Service
After=network.target

[Service]
WorkingDirectory=/opt/netfirewall/wanmonitor
ExecStart=/usr/bin/nice -n -20 /opt/netfirewall/wanmonitor/NetFirewall.WanMonitor
Restart=always
RestartSec=10
SyslogIdentifier=wanmonitor
KillSignal=SIGINT
Environment=ASPNETCORE_ENVIRONMENT=Production
Environment=DOTNET_PRINT_TELEMETRY_MESSAGE=false

[Install]
WantedBy=multi-user.target
6. Change the appsettings.json file to match your network configuration 
   
7. Run the following commands:
    sudo systemctl daemon-reload
    sudo systemctl enable netfirewall-wanmonitor
    sudo systemctl start netfirewall-wanmonitor
```

