insert into dhcp_config (id, ip_range_start, ip_range_end, subnet_mask, lease_time, gateway, dns_servers, boot_file_name, server_ip, server_name, description)
values (uuid_generate_v4(),'192.168.99.100','192.168.99.199','255.255.255.0',86400,'192.168.99.1',
        '{1.1.1.1,8.8.8.8}','/pxelinux.0','192.168.99.2','dhcp-server','server');