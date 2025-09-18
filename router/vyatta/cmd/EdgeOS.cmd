set firewall group network-group NETS_PRIVATE network 10.0.0.0/8
set firewall group network-group NETS_PRIVATE network 172.16.0.0/12
set firewall group network-group NETS_PRIVATE network 192.168.0.0/16

set firewall group address-group LIBERTY_ADDRESS_GRP address 8.8.8.8
set firewall group address-group LIBERTY_ADDRESS_GRP address 8.8.4.4
set firewall group address-group LIBERTY_ADDRESS_GRP description 'ipset for jailbreak destinations'
set firewall group port-group PORT_GFW_EXEMPTED port 22
set firewall group port-group PORT_GFW_EXEMPTED port 28022
set firewall group port-group PORT_GFW_EXEMPTED description "ssh ports do not need jailbreak"
set firewall group network-group NETS_GLOBAL description 'Global networks'
set firewall group address-group ADDR_GLOBAL description 'Global addresses'

set firewall modify PBR rule 10 action modify
set firewall modify PBR rule 10 destination group network-group NETS_PRIVATE
set firewall modify PBR rule 10 modify table main
set firewall modify PBR rule 20 action modify
set firewall modify PBR rule 20 description 'wan inteface'
set firewall modify PBR rule 20 destination group address-group ADDRv4_pppoe0
set firewall modify PBR rule 20 modify table main
set firewall modify PBR rule 30 action modify
set firewall modify PBR rule 30 description 'jailbreak on specified IT op ports with specified servers only'
set firewall modify PBR rule 30 destination group address-group LIBERTY_ADDRESS_GRP
set firewall modify PBR rule 30 destination group port-group PORT_GFW_EXEMPTED
set firewall modify PBR rule 30 modify table 100
set firewall modify PBR rule 30 protocol tcp_udp
set firewall modify PBR rule 31 action accept
set firewall modify PBR rule 31 description 'no jailbreak on specified IT op ports'
set firewall modify PBR rule 31 destination group port-group PORT_GFW_EXEMPTED
set firewall modify PBR rule 31 protocol tcp_udp
set firewall modify PBR rule 100 action modify
set firewall modify PBR rule 100 description 'Global network fwd to USA'
set firewall modify PBR rule 100 modify table 100
set firewall modify PBR rule 100 source group network-group NETS_GLOBAL
set firewall modify PBR rule 101 action modify
set firewall modify PBR rule 101 description 'Global addresses fwd to USA'
set firewall modify PBR rule 101 modify table 100
set firewall modify PBR rule 101 source group address-group ADDR_GLOBAL
set firewall modify PBR rule 110 action modify
set firewall modify PBR rule 110 description 'Smart split traffic'
set firewall modify PBR rule 110 destination group address-group LIBERTY_ADDRESS_GRP
set firewall modify PBR rule 110 modify table 100

set service dhcp-server use-dnsmasq enable
set service dns forwarding options enable-tftp
set service dns forwarding options tftp-root=/config/user-data/tftproot
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
set service dns forwarding options conf-dir=/config/user-data/conf

set system task-scheduler task dnsamsq-update crontab-spec '0 0 * * 1'
set system task-scheduler task dnsamsq-update executable path /config/user-data/bin/update_dnsmasq_rulesets.sh
set system task-scheduler task gfw-update executable arguments '-b wg251'
set system task-scheduler task gfw-update executable path /config/user-data/bin/gfw_peer_update.sh
set system task-scheduler task gfw-update interval 2m
set system task-scheduler task wg-update executable path /config/user-data/bin/wg_peer_update.sh
set system task-scheduler task wg-update interval 2m
