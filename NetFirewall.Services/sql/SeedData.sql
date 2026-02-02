insert into dhcp_config (id, ip_range_start, ip_range_end, subnet_mask, lease_time, gateway, dns_servers, boot_file_name, server_ip, server_name, description)
values (uuid_generate_v4(),'192.168.99.100','192.168.99.199','255.255.255.0',86400,'192.168.99.1',
        '{1.1.1.1,8.8.8.8}','/pxelinux.0','192.168.99.2','dhcp-server','server');


-- Crear el subnet principal
INSERT INTO dhcp_subnets (name,network,subnet_mask,router,dns_servers,default_lease_time,max_lease_time,tftp_server,boot_filename,interface_name,enabled)
VALUES ('LAN Principal',
        '192.168.99.0/24',
        '255.255.255.0',
        '192.168.99.1',
        ARRAY ['1.1.1.1'::inet, '8.8.8.8'::inet, '8.8.4.4'::inet],
        86400, -- 1 día
        604800, -- 7 días max
        '192.168.99.1',
        '/pxelinux.0',
        'ens256', -- interfaz LAN según tu Schema.sql
        true);

-- Crear el pool de IPs (excluyendo IPs reservadas bajas y altas)
INSERT INTO dhcp_pools (subnet_id,name,range_start,range_end,allow_unknown_clients,enabled)
VALUES ((SELECT id FROM dhcp_subnets WHERE name = 'LAN Principal'),
        'Pool Principal',
        '192.168.99.100',
        '192.168.99.199',
        true,
        true);

-- Opcional: Excluir rangos de IPs reservadas (servidores, APs, etc.)
-- Estas exclusiones previenen que el DHCP asigne IPs en estos rangos
INSERT INTO dhcp_exclusions (subnet_id, ip_start, ip_end, reason)
VALUES ((SELECT id FROM dhcp_subnets WHERE name = 'LAN Principal'), '192.168.99.1', '192.168.99.19',
        'Servidores e infraestructura'),
       ((SELECT id FROM dhcp_subnets WHERE name = 'LAN Principal'), '192.168.99.200', '192.168.99.254',
        'Impresoras y Access Points');

-- DHCP MAC Reservations                                                                                                                                                        
insert into dhcp_mac_reservations (mac_address, reserved_ip, description) values
    ('00:04:f2:4f:64:be', '192.168.99.26', 'Polycom_VVX1500'),
    ('64:16:7f:bd:b9:13', '192.168.99.27', 'PolycomVVX411'),
    ('64:16:7f:be:07:ef', '192.168.99.28', 'Polycom_VVX411'),
    ('00:04:f2:66:57:23', '192.168.99.29', 'Polycom_VVX600'),
    ('e0:69:95:35:af:dd', '192.168.99.20', 'MarvinPC'),
    ('18:31:bf:6c:cc:07', '192.168.99.22', 'ASUS_DESKTOP'),
    ('3c:52:82:25:c0:54', '192.168.99.200', 'HPPrinterM176N'),
    ('60:03:08:8f:20:da', '192.168.99.30', 'MacBookProNia'),
    ('e2:bc:29:71:4e:df', '192.168.99.31', 'MacBookProOld'),
    ('f8:59:71:0d:f1:fb', '192.168.99.32', 'Laptop Lenovo Flex 5 Wendy'),
    ('d0:11:e5:17:a2:cd', '192.168.99.38', 'Mac Mini M4 WiFi'),
    ('d0:11:e5:1b:19:82', '192.168.99.33', 'Mac Mini M4 Ethernet'),
    ('08:d2:3e:28:cd:64', '192.168.99.51', 'DiegoPC'),
    ('14:f6:d8:da:7d:e3', '192.168.99.50', 'MarvincitoPC'),
    ('00:1c:b3:71:06:a8', '192.168.99.35', 'iMac Stephania'),
    ('8c:79:f5:d9:c8:c0', '192.168.99.62', 'Samsung Smart TV'),
    ('f0:f0:a4:f3:e3:a9', '192.168.99.66', 'FireTV_4K'),
    ('48:43:dd:32:02:3a', '192.168.99.60', 'amazon-e70a45b55'),
    ('1c:fe:2b:13:79:eb', '192.168.99.61', 'amazon-4fa46ba36 Studio'),
    ('ec:2c:e2:b3:1c:90', '192.168.99.34', 'Stephanias-iPad'),
    ('28:a0:2b:2e:c7:78', '192.168.99.52', 'Diego iPhone'),
    ('34:08:bc:c9:01:08', '192.168.99.53', 'Marvincito iPhone'),
    ('fc:ec:da:b6:14:73', '192.168.99.249', 'Unifi AP 1'),
    ('fc:ec:da:fc:af:a7', '192.168.99.250', 'Unifi AP 2'),
    ('74:83:c2:26:34:04', '192.168.99.251', 'Unifi AP 3'),
    ('00:0c:29:b7:3b:f8', '192.168.99.3', 'RHELSQLServer'),
    ('f0:4d:a2:3d:52:7e', '192.168.99.4', 'TK1'),
    ('14:fe:b5:ca:c2:40', '192.168.99.5', 'TK2'),
    ('00:0c:29:2d:b0:1f', '192.168.99.6', 'PBX New'),
    ('00:0c:29:24:a3:d5', '192.168.99.9', 'debian VM Debian 10 x64'),
    ('00:0c:29:ec:6c:69', '192.168.99.10', 'DevServer Windows 2019'),
    ('00:0c:29:db:88:df', '192.168.99.14', 'FusionPBX for Dev'),
    ('00:0c:29:8b:5f:40', '192.168.99.11', 'VM Reserved'),
    ('00:0c:29:cd:0d:49', '192.168.99.13', 'VM Reserved'),
    ('00:0c:29:ec:74:35', '192.168.99.15', 'VM Reserved'),
    ('96:bd:da:12:6c:db', '192.168.99.36', 'Wendy iPad'),
    ('a2:5f:3f:ea:05:62', '192.168.99.24', 'MCh iPhone'),
    ('98:fa:9b:d9:f8:62', '192.168.99.21', 'Laptop Lenovo Legion Ethernet'),
    ('00:0c:29:db:65:92', '192.168.99.16', 'Ubuntu VM Desktop'),
    ('00:0c:29:93:13:d2', '192.168.99.18', 'Fusion Test'),
    ('00:0c:29:7f:3f:ac', '192.168.99.8', 'PBX Asterisk'),
    ('9c:ae:d3:b5:1a:d3', '192.168.99.201', 'Epson Printer Workforce WF-C5790'),
    ('74:78:27:e6:e0:0d', '192.168.99.37', 'Wendy Dock Ethernet'),
    ('a0:d0:5b:2d:4b:e0', '192.168.99.67', 'Samsung Smart TV Studio'),
    ('6c:4b:90:3a:fa:fb', '192.168.99.90', 'sbc-demo'),
    ('00:41:0e:66:cf:b7', '192.168.99.25', 'MCHLAPTOP'),
    ('f4:12:da:24:b9:44', '192.168.99.68', 'Claro TV+ Caja 1 Estudio'),
    ('f4:12:da:24:b2:6b', '192.168.99.69', 'Claro TV+ Caja 2 Main Room Ethernet'),
    ('bc:2b:02:1c:1e:19', '192.168.99.70', 'Claro TV+ Caja 2 Main Room WiFi'),
    ('f4:12:da:24:b3:14', '192.168.99.71', 'Claro TV+ Caja 3 Living Room Ethernet'),
    ('bc:2b:02:1c:1e:8b', '192.168.99.72', 'Claro TV+ Caja 3 Living Room WiFi'),
    ('04:f4:d8:a1:f7:6b', '192.168.99.73', 'TV TCL Sala'),
    ('bc:2b:02:29:81:96', '192.168.99.74', 'Claro TV Studio'),
    ('bc:2b:02:1e:22:ef', '192.168.99.75', 'Claro TV Sala -> TCL TV');