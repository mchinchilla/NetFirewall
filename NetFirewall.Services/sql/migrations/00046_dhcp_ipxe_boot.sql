-- 00046_dhcp_ipxe_boot.sql
-- iPXE chainloading. A PXE ROM loads an iPXE binary (boot_filename / boot_filename_uefi);
-- iPXE then DHCPs AGAIN (user class "iPXE") and, handed the same binary, loops forever.
-- boot_filename_ipxe is what an iPXE client gets instead — typically an HTTP script URL
-- (http://192.168.1.1/boot.ipxe). NULL = iPXE clients get the normal boot file.
ALTER TABLE dhcp_subnets ADD COLUMN IF NOT EXISTS boot_filename_ipxe varchar(512);
