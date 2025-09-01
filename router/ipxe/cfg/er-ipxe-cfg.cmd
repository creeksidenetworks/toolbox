set service dhcp-server use-dnsmasq enable
set service dns forwarding options enable-tftp
set service dns forwarding options tftp-root=/config/user-data/ipxe/tftproot
set service dns forwarding options 'dhcp-match=set:bios,60,PXEClient:Arch:00000'
set service dns forwarding options 'dhcp-match=set:efi32,60,PXEClient:Arch:00002'
set service dns forwarding options 'dhcp-match=set:efi32-1,60,PXEClient:Arch:00006'
set service dns forwarding options 'dhcp-match=set:efi64,60,PXEClient:Arch:00007'
set service dns forwarding options 'dhcp-match=set:efi64-1,60,PXEClient:Arch:00008'
set service dns forwarding options 'dhcp-match=set:efi64-2,60,PXEClient:Arch:00009'
set service dns forwarding options 'dhcp-boot=tag:bios,undionly.kpxe'
set service dns forwarding options 'dhcp-boot=tag:efi32,ipxe.efi'
set service dns forwarding options 'dhcp-boot=tag:efi32-1,ipxe.efi'
set service dns forwarding options 'dhcp-boot=tag:efi64,ipxe.efi'
set service dns forwarding options 'dhcp-boot=tag:efi64-1,ipxe.efi'
set service dns forwarding options 'dhcp-boot=tag:efi64-2,ipxe.efi'
set service dns forwarding options 'dhcp-userclass=set:ipxe,iPXE'
set service dns forwarding options 'dhcp-boot=tag:ipxe,http://ipxe.creekside.network/boot.ipxe'