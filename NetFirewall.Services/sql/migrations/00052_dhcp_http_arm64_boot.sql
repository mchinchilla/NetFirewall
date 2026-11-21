-- 00052_dhcp_http_arm64_boot.sql
-- Boot files by client type. Until now every UEFI client — ARM64 and UEFI HTTP boot included —
-- got boot_filename_uefi (an x64 TFTP file): ARM machines loaded the wrong binary and HTTP boot
-- firmware, which wants a URI and an "HTTPClient" offer, never booted.
--   boot_filename_http  : URI for UEFI HTTP boot clients (option 60 "HTTPClient…"). NULL = they get
--                         an address and no boot options.
--   boot_filename_arm64 : TFTP boot file for ARM64 UEFI (arch 11). NULL = the UEFI file, as before.
-- 255 = what option 67 can carry.
ALTER TABLE dhcp_subnets ADD COLUMN IF NOT EXISTS boot_filename_http  varchar(255);
ALTER TABLE dhcp_subnets ADD COLUMN IF NOT EXISTS boot_filename_arm64 varchar(255);
