# DHCP Server Feature Comparison: NetFirewall vs ISC-DHCP

## Resumen Ejecutivo

| Categoría | ISC-DHCP | NetFirewall | Estado |
|-----------|----------|-------------|--------|
| RFC 2131 Core | 100% | ~70% | En progreso |
| RFC 2132 Options | 100% | ~30% | Parcial |
| Failover | ✅ | ❌ | Pendiente |
| DDNS | ✅ | ❌ | Pendiente |
| DHCPv6 | ✅ | ❌ | Pendiente |
| PXE/UEFI | ✅ | Parcial | En progreso |
| Multi-subnet | ✅ | ❌ | Pendiente |
| Relay Agent | ✅ | Parcial | En progreso |

---

## 1. RFC 2131 - DHCP Protocol Core

### Mensajes DHCP
| Feature | ISC-DHCP | NetFirewall | Prioridad |
|---------|----------|-------------|-----------|
| DHCPDISCOVER | ✅ | ✅ | - |
| DHCPOFFER | ✅ | ✅ | - |
| DHCPREQUEST | ✅ | ✅ | - |
| DHCPACK | ✅ | ✅ | - |
| DHCPNAK | ✅ | ✅ | - |
| DHCPDECLINE | ✅ | ✅ | - |
| DHCPRELEASE | ✅ | ✅ | - |
| DHCPINFORM | ✅ | ✅ | - |
| DHCPFORCERENEW (RFC 3203) | ✅ | ❌ | Media |
| DHCPLEASEQUERY (RFC 4388) | ✅ | ❌ | Baja |

### Comportamiento del Protocolo
| Feature | ISC-DHCP | NetFirewall | Prioridad |
|---------|----------|-------------|-----------|
| Broadcast flag (bit 15) | ✅ | ✅ | - |
| T1 Renewal time (50%) | ✅ | ✅ | - |
| T2 Rebinding time (87.5%) | ✅ | ✅ | - |
| XID matching | ✅ | ✅ | - |
| Lease state machine | ✅ | Parcial | Alta |
| Relay agent (giaddr) | ✅ | Parcial | Alta |
| Option overloading | ✅ | ❌ | Media |

---

## 2. RFC 2132 - DHCP Options

### Opciones Básicas (Implementadas)
| Code | Nombre | ISC-DHCP | NetFirewall |
|------|--------|----------|-------------|
| 1 | Subnet Mask | ✅ | ✅ |
| 3 | Router (Gateway) | ✅ | ✅ |
| 6 | DNS Servers | ✅ | ✅ |
| 51 | Lease Time | ✅ | ✅ |
| 53 | Message Type | ✅ | ✅ |
| 54 | Server Identifier | ✅ | ✅ |
| 58 | Renewal Time (T1) | ✅ | ✅ |
| 59 | Rebinding Time (T2) | ✅ | ✅ |

### Opciones Faltantes (Prioridad Alta)
| Code | Nombre | Uso | Prioridad |
|------|--------|-----|-----------|
| 12 | Hostname | Cliente reporta nombre | Alta |
| 15 | Domain Name | Dominio de búsqueda DNS | Alta |
| 28 | Broadcast Address | Broadcast de la red | Alta |
| 42 | NTP Servers | Sincronización de tiempo | Alta |
| 44 | NetBIOS Name Server (WINS) | Redes Windows | Media |
| 46 | NetBIOS Node Type | Redes Windows | Media |
| 66 | TFTP Server Name | PXE Boot | ✅ Parcial |
| 67 | Bootfile Name | PXE Boot | ✅ Parcial |
| 119 | Domain Search List | Múltiples dominios DNS | Alta |
| 121 | Classless Static Routes | Rutas estáticas modernas | Alta |

### Opciones Faltantes (Prioridad Media)
| Code | Nombre | Uso |
|------|--------|-----|
| 2 | Time Offset | Zona horaria |
| 4 | Time Server | Servidores de tiempo |
| 7 | Log Server | Syslog |
| 26 | Interface MTU | MTU de red |
| 33 | Static Route | Rutas estáticas (obsoleto) |
| 43 | Vendor Specific | Opciones de fabricante |
| 60 | Vendor Class ID | Identificación de cliente |
| 77 | User Class | Clasificación de usuario |
| 81 | Client FQDN | Nombre completo del cliente |
| 82 | Relay Agent Info | Información del relay |

### Opciones Faltantes (Prioridad Baja)
| Code | Nombre |
|------|--------|
| 5 | Name Server (IEN 116) |
| 8-11 | Servidores obsoletos |
| 13 | Boot File Size |
| 16-25 | Opciones de red obsoletas |
| 34-39 | Opciones TCP |
| 40-41 | NIS |
| 48-49 | X Window |

---

## 3. Features Avanzados

### Multi-Subnet y Pools
| Feature | ISC-DHCP | NetFirewall | Prioridad |
|---------|----------|-------------|-----------|
| Múltiples subnets | ✅ | ❌ | **Crítica** |
| Múltiples pools por subnet | ✅ | ❌ | **Crítica** |
| Shared networks | ✅ | ❌ | Alta |
| Pool ranges dinámicos | ✅ | Parcial | Alta |
| Exclusiones de IP | ✅ | ❌ | Alta |

### Alta Disponibilidad
| Feature | ISC-DHCP | NetFirewall | Prioridad |
|---------|----------|-------------|-----------|
| Failover Protocol (RFC 3074) | ✅ | ❌ | Alta |
| Load balancing | ✅ | ❌ | Media |
| State synchronization | ✅ | ❌ | Alta |
| Split leases | ✅ | ❌ | Media |

### DDNS (Dynamic DNS)
| Feature | ISC-DHCP | NetFirewall | Prioridad |
|---------|----------|-------------|-----------|
| Forward DNS updates | ✅ | ❌ | Alta |
| Reverse DNS updates | ✅ | ❌ | Alta |
| TSIG authentication | ✅ | ❌ | Alta |
| Conflict detection | ✅ | ❌ | Media |

### Clasificación y Políticas
| Feature | ISC-DHCP | NetFirewall | Prioridad |
|---------|----------|-------------|-----------|
| Classes | ✅ | ❌ | Alta |
| Subclasses | ✅ | ❌ | Media |
| Match statements | ✅ | ❌ | Alta |
| Pool allow/deny | ✅ | ❌ | Alta |
| Vendor class matching | ✅ | ❌ | Media |

### PXE Boot
| Feature | ISC-DHCP | NetFirewall | Prioridad |
|---------|----------|-------------|-----------|
| Basic PXE | ✅ | ✅ | - |
| UEFI detection | ✅ | ❌ | Alta |
| Legacy BIOS detection | ✅ | ❌ | Alta |
| iPXE chainloading | ✅ | ❌ | Media |
| Boot menu | ✅ | ❌ | Media |
| Architecture-specific files | ✅ | ❌ | Alta |

### Eventos y Hooks
| Feature | ISC-DHCP | NetFirewall | Prioridad |
|---------|----------|-------------|-----------|
| on commit | ✅ | ❌ | Alta |
| on release | ✅ | ❌ | Alta |
| on expiry | ✅ | ❌ | Alta |
| Custom scripts | ✅ | ❌ | Alta |

---

## 4. Roadmap de Implementación

### Fase 1: Core Completeness (Crítico)
1. [ ] Multi-subnet support
2. [ ] Múltiples pools
3. [ ] Opciones 12, 15, 28 (Hostname, Domain, Broadcast)
4. [ ] Opción 119 (Domain Search List)
5. [ ] Opción 121 (Classless Static Routes)
6. [ ] Relay agent completo (giaddr processing)

### Fase 2: Enterprise Features (Alta)
1. [ ] DDNS integration
2. [ ] NTP servers (opción 42)
3. [ ] Clasificación por MAC/Vendor
4. [ ] Pool allow/deny rules
5. [ ] Event hooks (on commit/release/expiry)
6. [ ] UEFI/Legacy PXE detection

### Fase 3: High Availability (Alta)
1. [ ] Failover protocol
2. [ ] State synchronization via PostgreSQL
3. [ ] Health monitoring
4. [ ] Automatic failback

### Fase 4: Advanced (Media)
1. [ ] DHCPv6 support
2. [ ] DHCPFORCERENEW
3. [ ] DHCPLEASEQUERY
4. [ ] Custom option definitions
5. [ ] Full vendor option support

---

## 5. Modelo de Datos Propuesto para Multi-Subnet

```sql
-- Subnets/Scopes
CREATE TABLE dhcp_subnets (
    id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    network CIDR NOT NULL,
    subnet_mask INET NOT NULL,
    router INET,
    broadcast INET,
    domain_name VARCHAR(255),
    dns_servers INET[],
    ntp_servers INET[],
    default_lease_time INT DEFAULT 86400,
    max_lease_time INT DEFAULT 604800,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Pools within subnets
CREATE TABLE dhcp_pools (
    id UUID PRIMARY KEY,
    subnet_id UUID REFERENCES dhcp_subnets(id),
    name VARCHAR(100),
    range_start INET NOT NULL,
    range_end INET NOT NULL,
    allow_unknown_clients BOOLEAN DEFAULT true,
    deny_bootp BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true
);

-- IP exclusions
CREATE TABLE dhcp_exclusions (
    id UUID PRIMARY KEY,
    subnet_id UUID REFERENCES dhcp_subnets(id),
    ip_start INET NOT NULL,
    ip_end INET NOT NULL,
    reason VARCHAR(255)
);

-- Classes for client classification
CREATE TABLE dhcp_classes (
    id UUID PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    match_expression TEXT, -- e.g., "vendor-class-identifier = 'PXEClient'"
    options JSONB,
    priority INT DEFAULT 100
);

-- Class assignments
CREATE TABLE dhcp_pool_classes (
    pool_id UUID REFERENCES dhcp_pools(id),
    class_id UUID REFERENCES dhcp_classes(id),
    allow BOOLEAN DEFAULT true,
    PRIMARY KEY (pool_id, class_id)
);
```

---

## 6. Conclusión

### Ventajas de NetFirewall DHCP sobre ISC-DHCP:
1. **Integración Web UI** - Gestión visual completa
2. **PostgreSQL Backend** - Clustering y alta disponibilidad de datos
3. **Observabilidad** - Logging estructurado, métricas
4. **API REST** - Integración con otros sistemas
5. **Moderno** - Async/await, .NET ecosystem

### Desventajas:
1. **Performance** - 5-10x más lento en raw throughput
2. **Madurez** - ISC tiene 25+ años de battle-testing
3. **Features** - ~30-40% de funcionalidad completa
4. **DHCPv6** - No soportado aún

### Recomendación:
Para redes pequeñas/medianas (<500 dispositivos), NetFirewall DHCP es viable.
Para redes enterprise (>1000 dispositivos), ISC-DHCP o Kea DHCP son más apropiados hasta que completemos las features faltantes.
