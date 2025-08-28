#!/bin/bash
# VyOS/EdgeRouter configuration utility v1
# Now support interactive 
# (c) 2021 Creekside Networks LLC, Jackson Tong
# Usage: ssh -t ip "$(<./router-setup.sh)"

# ****************************************************************************
SCRIPT_VERSION="8.0"
#DEBUG_ON${Yellow}="Y"

# Formats
Black=`tput setaf 0`	#${Black}
Red=`tput setaf 1`	#${Red}
Green=`tput setaf 2`	#${Green}
Yellow=`tput setaf 3`	#${Yellow}
Blue=`tput setaf 4`	#${Blue}
Magenta=`tput setaf 5`	#${Magenta}
Cyan=`tput setaf 6`	#${Cyan}
White=`tput setaf 7`	#${White}
Bold=`tput bold`	#${Bold}
UndrLn=`tput sgr 0 1`	#${UndrLn}
Rev=`tput smso`		#${Rev}
Reset=`tput sgr0`	#${Reset}

SSH_PORT=22
GUI_PORT=8843
UNMS_KEY_US="wss://creeksidenetworks.unmsapp.com:443+8cdcCAHWDp3AUWeld1JhD3xYupAYJVA6AgIyPpsvBDZ6supB+allowSelfSignedCertificate"
UNMS_KEY_CN="wss://uisp-cn.creeksidenet.com:8443+8scipGbAsTTuyAZ7upOAF6WUX16DOwMRM0com29l5KAvpKau+allowSelfSignedCertificate"

DEFAULT_DMZ_VLAN=255
DEFAULT_GLOBAL_VLAN=254
GRE_TUNNEL_MTU=1390
# NMS & ftp servers
DEFAULT_DOMAIN=creekside.network
NMS_SERVER=nms.$DEFAULT_DOMAIN
FTP_SERVER=ftp.$DEFAULT_DOMAIN
#FTP_SERVER=10.3.10.50

# configuration directories
CREEKSIDE_ROOT=/config/creekside
CFG_DIR=$CREEKSIDE_ROOT/conf
SCRIPTS_DIR=$CREEKSIDE_ROOT/scripts
DEB_DIR=$CREEKSIDE_ROOT/deb
IPSEC_DIR=$CREEKSIDE_ROOT/ipsec
AUTH_DIR=auth

LOCAL_CFG_FILE=$CFG_DIR/local-host.conf
CREEKSIDE_CFG_SCRIPT="/tmp/creekside_cfg.sh"
LOCAL_SITE_FILE="$CFG_DIR/local-host.site"
OLD_CFG_FILE=/config/user-data/local/local-host.conf

ADMIN_PASSWORD="Oakridge2016!"
JTONG_PASSWORD=$ADMIN_PASSWORD

LOG_FILE=/var/log/creekside.log
REMOTLOG_CONF=$CFG_DIR/remote-log.conf
LOG_LEVEL="DETAIL"

CF_DDNS_CONF_FILE=$CFG_DIR/cloudflare-dƒ.conf
CF_DDNS_UPDATE_SCRIPT=$SCRIPTS_DIR/cloudflare-update.sh

WIREGUARD_RELEASE="1.0.20220627"
WIREGUARD_TOOLS="1.0.20210914"
WIREGUARD_DEB_V1=$DEB_DIR/wireguard-v1.deb
WIREGUARD_DEB_V2=$DEB_DIR/wireguard-v2.deb
WIREGUARD_CONF_FILE=$CFG_DIR/wireguard.conf
WIREGUARD_PEER_FILE=$CFG_DIR/wireguard-peers.conf
WIREGUARD_BRINGUP_SCRIPTS=$SCRIPTS_DIR/wireguard-bringup.sh
WIREGUARD_UPDATE_SCRIPTS=$SCRIPTS_DIR/wireguard-update.sh
SPEEDTEST_SCRIPTS=$SCRIPTS_DIR/speedtest
WIREGUARD_PORT_SITE="52800"
WIREGUARD_PORT_DIAL="52801"

WIREGUARD_IT_PUB="x0Rnj+TUpD44TevyUHKhu/xIXihacRRjm2uP6Jh7S1Q="
WG0_KEY_FILE="/config/auth/wireguard/wg0/private.key"
WG0_PUB_FILE="/config/auth/wireguard/wg0/public.key"
WG1_KEY_FILE="/config/auth/wireguard/wg1/private.key"
WG1_PUB_FILE="/config/auth/wireguard/wg1/public.key"

# DNSMASQ-IPSET files
DNSMASQ_GFW_CONF=$CFG_DIR/dnsmasq_gfwlist_ipset.conf
DNSMASQ_CUSTOM_CONF=$CFG_DIR/dnsmasq_custom_ipset.conf
DNSMASQ_CONF_FILE=/etc/dnsmasq.conf

GLOBAL_DNS=8.8.8.8
GLOBAL_DNS2=1.1.1.1
GLOBAL_DNS3=9.9.9.9

CHINA_DNS1=223.5.5.5
CHINA_DNS2=119.29.29.29
CHINA_DNS3=114.114.114.114

# SDWAN servers
SDWAN_CONF_FILE=$CFG_DIR/sdwan.conf
SDWAN_PEERS_CONF=$CFG_DIR/sdwan-peers.conf
SDWAN_UPDATE_SCRIPTS=$SCRIPTS_DIR/sdwan-update.sh

# install options
GFW_BREAK_ENABLED="N"
GFW_RELAY_ENABLED="N"
DMZNET_ENABLED="N"
GLOBALNET_ENABLED="N"

TCP_MSS="1300"

# temporary working directory
WORK_DIR=/tmp/work

# Roadwarrior VPN
IPSEC_SERVER_KEY=/config/ipsec.d/rsa-keys/localhost.key
IPSEC_SERVER_PUB=/config/ipsec.d/rsa-keys/localhost.pub

IPSEC_CA_CERT=$IPSEC_DIR/cacerts/creekside.authority.cer
IPSEC_CA_KEY=/tmp/creekside.key
IPSEC_CSR=/tmp/ipsec.csr
IPSEC_CSR_EXT=/tmp/ipsec-csr.ext

IPSEC_SERVER_CER=$IPSEC_DIR/certs/server.cer

IPSEC_CONF=$IPSEC_DIR/ipsec.conf
IPSEC_SECRETS=$IPSEC_DIR/ipsec.secrets
IPSEC_STRONGSWAN_CONF=$IPSEC_DIR/strongswan.conf
IPSEC_RADIUS_USER=$IPSEC_DIR/radius-users

# boot up scripts
CREEKSIDE_BOOTUP_SCRIPTS="/config/scripts/post-config.d/creekside-bootup.sh"

# creekside default unifi controller
CREEKSIDE_UNIFI_FQDN="unifi.creekside.network"

# pre-defined edgeos commands
ROUTER_CFGCMD=/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper
ROUTER_RUNCMD=/opt/vyatta/bin/vyatta-op-cmd-wrapper

DISABLE_SSH_PASSWD="Y"
DISABLE_WEB_ACCESS="N"


# check if the domain name is managed by Creekside
function Check_Creekside_Managed_Domain() {
    case $1 in 
        "creekside.network" | "creeksidenet.com" | "dreambigsemi.net" | "adapsphotonics.net" | "innousa.net")
            return 0
            ;;
        "chemshuttle.net")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# local-host.conf operations
function Load_Localhost_Cfg() {
    local i
    local j

    if sudo test -f $LOCAL_CFG_FILE; then
        while read -r VAR VALUE REMINDER; do
            case $VAR in
                "VER")
                    CFG_VER=$VALUE
                    ;;
                "ID")
                    LOCAL_ID=$VALUE
                    ;;
                "HOSTNAME")
                    ROUTER_HOSTNAME=$VALUE
                    ;;
                "ROADWARRIOR_ENABLED")
                    ROADWARRIOR_ENABLED=$VALUE
                    ;;
                "ROADWARRIOR_DMZ_ENABLED")
                    ROADWARRIOR_DMZ_ENABLED=$VALUE
                    ;;
                "GFW_BREAK_ENABLED")
                    GFW_BREAK_ENABLED=$VALUE
                    ;;
                "WAN_IF")
                    cfg_wan_name[0]=$VALUE
                    ;;
                "FQDN1"| "FQDN")
                    cfg_wan_host[0]=$VALUE
                    ;;
                "WAN2_IF")
                    cfg_wan_name[1]=$VALUE
                    ;;
                "FQDN2")
                    cfg_wan_host[1]=$VALUE
                    ;;
                "ROADWARRIOR_ENABLED")
                    ROADWARRIOR_ENABLED=$VALUE
                    ;;
                "GFW_BREAK")
                    GFW_BREAK_ENABLED=$VALUE
                    ;;
                "GFW_RELAY_ENABLED")
                    GFW_RELAY_ENABLED=$VALUE
                    ;;
                "GLOBALNET_ENABLED")
                    GLOBALNET_ENABLED=$VALUE
                    ;;
                "GLOBALNET_IF")
                    GLOBALNET_IF=$VALUE
                    ;;
                "DMZNET_ENABLED")
                    DMZNET_ENABLED=$VALUE
                    ;;
                "DMZNET_IF")
                    DMZNET_IF=$VALUE
                    ;;
                "LOOPBACK_IP")
                    LOOPBACK_IP=$VALUE
                    ;;
                "COUNTRY")
                    COUNTRY=$VALUE
                    ;;
                "TIMEZONE")
                    TIMEZONE=$VALUE
                    ;;
                "IPA_ENABLED")
                    IPA_ENABLED=$VALUE
                    ;;
                "IPA_HOSTNAME")
                    IPA_HOSTNAME=$VALUE
                    ;;
                "IPA_DOMAIN")
                    IPA_DOMAIN=$VALUE
                    ;;
                "IPA_SERVER_IP")
                    IPA_SERVER_IP=$VALUE
                    ;;
                "SECURE_ZONE")
                    ZONE_POLICY_SECURE=$VALUE
                    ;;
                "DMZ_ZONE")
                    ZONE_POLICY_DMZ=$VALUE
                    ;;
                "INTERNAL_ZONE")
                    ZONE_POLICY_INTERNAL=$VALUE
                    ;;
                "PUBLIC_ZONE")
                    ZONE_POLICY_PUBLIC=$VALUE
                    ;;
                "LOCAL_DOMAIN")
                    LOCAL_DOMAIN=$VALUE
                    ;;
                "LOCAL_NS_ADDR")
                    LOCAL_NS_ADDR=$VALUE
                    ;;
                "LOCAL_NAMESERVER_ENABLED")
                    LOCAL_NAMESERVER_ENABLED=$VALUE
                    ;;
                "LOCAL_WG0_IP")
                    LOCAL_WG0_IP=$VALUE
                    ;;
                "LOCAL_WG0_PORT")
                    LOCAL_WG0_PORT=$VALUE
                    ;;
                "LOCAL_WG0_PUB")
                    LOCAL_WG0_PUB=$VALUE
                    ;;
                "LOCAL_WG0_KEY")
                    LOCAL_WG0_KEY=$VALUE
                    ;;
                *)
                    # load wanif name & fqdn
                    if [[ $VAR =~ ^WAN_NAME[0-9] ]]; then
                        index=${VAR//[!0-9]/}  
                        cfg_wan_name[$index]=$VALUE
                    elif [[ $VAR =~ ^WAN_HOST[0-9] ]]; then
                        index=${VAR//[!0-9]/}  
                        WAN_FQDN[$index]=$VALUE
                    elif [[ $VAR =~ ^WAN_FQDN[0-9] ]]; then
                        index=${VAR//[!0-9]/}  
                        WAN_FQDN[$index]=$VALUE
                    elif [[ $VAR =~ ^LAN_NAME[0-9] ]]; then
                        index=${VAR//[!0-9]/}  
                        cfg_lan_name[$index]=${VALUE%%.*}
                    elif [[ $VAR =~ ^LAN_ZONE[0-9] ]]; then
                        index=${VAR//[!0-9]/}  
                        cfg_lan_zone[$index]=${VALUE%%.*}
                    fi
                    ;;
            esac
        done < $LOCAL_CFG_FILE

        #we should match the cfg wan/fqdn to the wan ports scanned
        i=0
        while [[ ${cfg_wan_name[$i]} != "" ]]; do
            for ((j=0; j<$NETIF_INDX; j++)) do
                if [[ ${cfg_wan_name[$i]} == ${NETIF_NAME[$j]} ]]; then
                    NETIF_HOST[$j]=${WAN_FQDN[$i]}
                    # for compatbility of old config, assign hostname to the 1st FQDN
                    ROUTER_HOSTNAME=${ROUTER_HOSTNAME:-${WAN_FQDN[$i]}}
                    break
                fi
            done

            i=$((i + 1))
        done

        i=0
        while [[ ${cfg_wan_name[$i]} != "" ]]; do
            for ((j=0; j<$NETIF_INDX; j++)) do
                if [[ ${cfg_lan_name[$i]} == ${NETIF_NAME[$j]} ]]; then
                    NETIF_ZONE[$j]=${cfg_lan_zone[$i]}
                    break
                fi
            done

            i=$((i + 1))
        done
        
        return 0
    else
        return 1
    fi
}

function Save_Config_Entry() {
    if [[ $2 != "" ]]; then
        printf "%-32s %s\n" "$1" "$2"  | sudo tee -a $LOCAL_CFG_FILE &> /dev/null
    fi
}

function Save_Localhost_Cfg() {
    local i
    local index=0
    local lan_index=0

    sudo rm -f $LOCAL_CFG_FILE

    Save_Config_Entry "VER"                     $SCRIPT_VERSION         
    Save_Config_Entry "ID"                      $LOCAL_ID               
    Save_Config_Entry "HOSTNAME"                $ROUTER_HOSTNAME          
    # save wan interfaces & related-fqdn information
    for((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_MODE[$i]} == "wan" ]]; then
            Save_Config_Entry "WAN_NAME$index"          ${NETIF_NAME[$i]}       
            Save_Config_Entry "WAN_HOST$index"          ${NETIF_HOST[$i]}  
            index=$((index + 1)) 
        fi

        if [[ ${NETIF_MODE[$i]} == "lan" ]] && [[ ${NETIF_ADDR[$i]} != '-' ]]; then
            Save_Config_Entry "LAN_NAME$lan_index"          ${NETIF_NAME[$i]}       
            Save_Config_Entry "LAN_ZONE$lan_index"          ${NETIF_ZONE[$i]}
            lan_index=$((lan_index + 1))   
        fi    
    done

    Save_Config_Entry "SECURE_ZONE"             $ZONE_POLICY_SECURE 
    Save_Config_Entry "DMZ_ZONE"              $ZONE_POLICY_DMZ 
    Save_Config_Entry "INTERNAL_ZONE"             $ZONE_POLICY_INTERNAL 
    Save_Config_Entry "PUBLIC_ZONE"           $ZONE_POLICY_PUBLIC 

    Save_Config_Entry "COUNTRY"                 $COUNTRY                
    Save_Config_Entry "TIMEZONE"                $TIMEZONE               

    Save_Config_Entry "DMZNET_IF"             $DMZNET_IF            
    Save_Config_Entry "DMZNET_ENABLED"        $DMZNET_ENABLED       

    Save_Config_Entry "ROADWARRIOR_ENABLED"     $ROADWARRIOR_ENABLED          
    Save_Config_Entry "GFW_BREAK_ENABLED"       $GFW_BREAK_ENABLED      
    Save_Config_Entry "GFW_RELAY_ENABLED"       $GFW_RELAY_ENABLED      
    Save_Config_Entry "GLOBALNET_IF"            $GLOBALNET_IF           
    Save_Config_Entry "GLOBALNET_ENABLED"       $GLOBALNET_ENABLED      

    Save_Config_Entry "IPA_ENABLED"             $IPA_ENABLED            
    Save_Config_Entry "IPA_HOSTNAME"            $IPA_HOSTNAME           
    Save_Config_Entry "IPA_DOMAIN"              $IPA_DOMAIN             
    Save_Config_Entry "IPA_SERVER_IP"           $IPA_SERVER_IP  

    Save_Config_Entry "LOCAL_DOMAIN"            $LOCAL_DOMAIN
    Save_Config_Entry "LOCAL_NS_ADDR"           $LOCAL_NS_ADDR
    Save_Config_Entry "LOCAL_NAMESERVER_ENABLED"        $LOCAL_NAMESERVER_ENABLED

    Save_Config_Entry "LOOPBACK_IP"             $LOOPBACK_IP

    # Wireguard info
    Save_Config_Entry "LOCAL_WG0_IP"            $LOCAL_WG0_IP
    Save_Config_Entry "LOCAL_WG0_PORT"          $LOCAL_WG0_PORT
    Save_Config_Entry "LOCAL_WG0_PUB"           $LOCAL_WG0_PUB
    Save_Config_Entry "LOCAL_WG0_KEY"           $LOCAL_WG0_KEY

    i=0
    while [[ ${VPN_DNSNAME[$i]} != "" ]]; do
        Save_Config_Entry "VPN_DNSNAME$i"       ${VPN_DNSNAME[$i]}
        i=$((i + 1))
    done
    Save_Config_Entry "VPN_LOCAL_ADDR"             $VPN_LOCAL_ADDR

    Save_Config_Entry "VPN_RADIUS_ENABLE"       $VPN_RADIUS_ENABLE
    Save_Config_Entry "VPN_RADIUS_ADDRESS"      $VPN_RADIUS_ADDRESS
    Save_Config_Entry "VPN_RADIUS_SECRET"       $VPN_RADIUS_SECRET
    Save_Config_Entry "VPN_SECURE_ENABLE"       $VPN_SECURE_ENABLE
    Save_Config_Entry "VPN_DMZ_ENABLE"        $VPN_DMZ_ENABLE
    Save_Config_Entry "ROADWARRIOR_DNS_ADDR"            $ROADWARRIOR_DNS_ADDR

    Save_Config_Entry "LAST_MODIFY"             $(date +"%Y-%m-%d-%H:%M") 
}

# Scan network port to find out WAN/LAN etc
function Scan_Network_Ports() {
    local i
    local j
    local interface
    local address
    local link 
    local description

    printf "\n o Scan network interfaces\n"
    NETIF_INDX=0
    
    while read -r interface address link description; do
        # bypass unrelated ports
#        if ! [[ $interface =~ ^eth[0-9.]+$ ]] && \
#           ! [[ $interface =~ ^switch[0-9.]+$ ]] && \
#           ! [[ $interface =~ ^pppoe[0-9]+$ ]]; then 
#           continue;
#        fi

#        if [[ $address == "-" ]]; then
#            continue
        if [[ $interface =~ ^eth[0-9]+$ ]]; then 
            NETIF_TYPE[$NETIF_INDX]="ethernet"
            NETIF_VLAN[$NETIF_INDX]="-"
            NETIF_MODE[$NETIF_INDX]="lan"
        elif [[ $interface =~ ^eth[0-9.]+$ ]]; then 
            NETIF_TYPE[$NETIF_INDX]="ethernet"
            NETIF_VLAN[$NETIF_INDX]=${interface##*.}
            NETIF_BASE[$NETIF_INDX]=${interface%.*}  
            NETIF_MODE[$NETIF_INDX]="lan"
        elif [[ $interface =~ ^switch[0-9]+$ ]]; then 
            NETIF_TYPE[$NETIF_INDX]="switch"
            NETIF_VLAN[$NETIF_INDX]="-"
            NETIF_MODE[$NETIF_INDX]="lan"
        elif [[ $interface =~ ^switch[0-9.]+$ ]]; then 
            NETIF_TYPE[$NETIF_INDX]="switch"
            NETIF_VLAN[$NETIF_INDX]=${interface##*.}
            NETIF_BASE[$NETIF_INDX]=${interface%.*} 
            NETIF_MODE[$NETIF_INDX]="lan"
        elif [[ $interface =~ ^pppoe[0-9]+$ ]]; then 
            NETIF_TYPE[$NETIF_INDX]="pppoe"
            NETIF_MODE[$NETIF_INDX]="wan"
            NETIF_VLAN[$NETIF_INDX]=${interface//[!0-9]/} 
        elif [[ $interface =~ ^tun[0-9]+$ ]]; then  
            NETIF_TYPE[$NETIF_INDX]="tunnel"
            NETIF_VLAN[$NETIF_INDX]="-"
            NETIF_MODE[$NETIF_INDX]="local"
        elif [[ $interface =~ ^wg[0-9]+$ ]]; then  
            NETIF_TYPE[$NETIF_INDX]="wireguard"
            NETIF_VLAN[$NETIF_INDX]="-"
            NETIF_MODE[$NETIF_INDX]="local"
        else
            continue
        fi

        NETIF_NAME[$NETIF_INDX]=$interface
        NETIF_DSCP[$NETIF_INDX]=$description
        link=${link##*/}
        link=${link^^}
        NETIF_LINK[$NETIF_INDX]=$link
        NETIF_ADDR[$NETIF_INDX]="$address"

        NETIF_INDX=$((NETIF_INDX + 1))
    done  < <($ROUTER_RUNCMD show interfaces)

    # exclude switch-ports
    if [[ $SWITCHIF == "Y" ]]; then
        while read -r interface mode reminder; do
            if [[ $mode == "switch" ]]; then
                for ((i=0; i<$NETIF_INDX; i++)) do
                    if [[ ${NETIF_NAME[$i]} == $interface ]]; then
                        NETIF_MODE[$i]="switch-port"
                        NETIF_DSCP[$i]="switch-port"
                        continue;
                    fi
                done
            fi
        done  < <($ROUTER_RUNCMD show interfaces switch switch0 switch-port)
    fi

    # find out wan interfaces
    local table_id
    WANIF_NUM=0

    while read -r interface reminder; do 
        interface=${interface%%,}
        # search NETIF databse to get address, link status
        for ((i=0; i<$NETIF_INDX; i++)) do
            if [[ ${NETIF_NAME[$i]} == $interface ]]; then
                NETIF_MODE[$i]="wan"
                WANIF_NUM=$((WANIF_NUM + 1))

                if [[ $interface =~ ^pppoe[0-9]+$ ]]; then
                    # find base interfaces of pppoe
                    interface=$(cat /etc/ppp/peers/$interface | grep "nic-eth")
                    interface=${interface##nic-}
                    NETIF_BASE[$i]=$interface
                    for ((j=0; j<$NETIF_INDX; j++)) do
                        if [[ ${NETIF_NAME[$j]} == $interface ]]; then
                            NETIF_MODE[$j]="pppoebase"
                            break
                        fi
                    done
                fi
                break
            fi
        done
    done < <(ip route | grep default | grep -o 'eth.*\|pppoe.*')
#    done < <($ROUTER_RUNCMD show ip route | grep "0.0.0.0/0" | grep -o 'eth.*\|pppoe.*')



    if [[ $WANIF_NUM == "0" ]]; then
        printf   "\n **** No internet connection found ****\n\n"
        exit 0
    fi

    printf "   - Internet\n"
    local index=0
    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_MODE[$i]} == "wan" ]]; then
            printf   "%-22s %-37s : %s\n" "     $index.${NETIF_NAME[$i]}" "${NETIF_ADDR[$i]}" "${NETIF_DSCP[$i]}" 
            index=$((index+1))
        fi
    done

    printf "   - Local\n"
    LANIF_NUM=0
    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_MODE[$i]} == "lan" ]]; then
            printf   "%-22s %-37s : %s\n" "     $LANIF_NUM.${NETIF_NAME[$i]}" "${NETIF_ADDR[$i]}" "${NETIF_DSCP[$i]}" 
            LANIF_NUM=$((LANIF_NUM+1))
        fi
    done
    if [[ $LANIF_NUM == "0" ]]; then
            printf    "     --- None ---\n" 
    fi 

    return $NETIF_INDX
}


# Test an IP address for validity:
function Valid_IP()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Test a hostname for validity:
function Valid_Hostname() {

    local hostname=$1

    # check host name only
    if [[ $hostname =~  ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61} ]]; then
        return 0
    elif [[ $hostname =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then 
        return 0
    else
        return 1
    fi
}

# Prompt user and get a valid ip address
function Read_IP() {
    local input
    local default=$2
    default=${default#*[}
    default=${default%]*}

    while [[ true ]]; do
        printf "%-42s %17s : " "$1" "[$2]"    
        read input

        input=${input:-$default}
   
        if Valid_IP $input; then
            READ_VALUE=$input
            return 0
        else
            printf "\n  *** A valid IPv4 address is required ***\n"
            continue
        fi
    done
}

# Prompt user and get a valid ip pool
function Read_IP_Pool24() {
    local input
    local default=$2
    default=${default#*[}
    default=${default%]*}

    while [[ true ]]; do
        printf "%-42s %17s : " "$1" "[$2]/24"    
        read input

        input=${input:-$default}
   
        if [[ $input == "-" ]]; then
            return 1
        elif Valid_IP $input; then
            READ_VALUE=$input
            return 0
        else
            printf "\n  *** A valid IPv4 address is required ***\n"
            continue
        fi
    done
}

# Prompt user and get a number in range
function Read_Number() {
    local input
    local default=$2
    local low=$3
    local high=$4

    while [[ true ]]; do
        printf "%-49s %10s : " "$1" "[$2]"    
        read input
        input=${input:-$default}

        if [[ $input -lt $low ]] || [[ $input -gt $high ]]; then
             printf "\n  *** '$input' is out of valid range [$low - $high] ***\n"
             continue;
        else
            READ_VALUE=$input
            return 0
        fi
    done
}


# Prompt user and get a choice of a menu
function Read_Choice() {
    local input
    local default=$2
    local low=$3
    local high=$4

    while [[ true ]]; do
        printf "\n%55s %4s : " "$1" "[$2]"    
        read input
        input=${input:-$default}

        if [[ $input -lt $low ]] || [[ $input -gt $high ]]; then
             printf "\n  *** '$input' is out of valid range [$low - $high] ***\n"
             continue;
        else
            READ_VALUE=$input
            return 0
        fi
    done
}

# Prompt user and get a string with limited size 
function Read_String() {
    local input
    local default=$2
    local low=$3
    local high=$4
    local default_shown

    if [[ ${#default} -gt 18 ]]; then
        default_shown="${default:0:15}..."
    else
        default_shown=$default
    fi

    while [[ true ]]; do
        printf "%-39s %20s : " "$1" "[$default_shown]"    
        read input
        input=${input:-$default}

        input_len=${#input}
        if [[ $input_len -lt $low ]] || [[ $input_len -gt $high ]]; then
             printf "\n  *** Length out of range [$low - $high] ***\n"
             continue;
        else
            READ_VALUE=$input
            return 0
        fi
    done
}

# Prompt user and get a valid domain
function Read_Domain() {
    local input
    local prompt=$1
    local default=$2


    while [[ true ]]; do
        printf "%-20s %39s : " "$prompt" "[$default]"    
        read input

        input=${input:-$default}

        if [[ $input =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then 
            READ_VALUE=$input
            return 0
        else
            printf "\n  *** A valid domain is required [$input] ***\n"
            continue
        fi
    done
}

# Prompt user and get a valid hostname
function Read_Hostname() {
    local input
    local prompt=$1
    local default=$2


    while [[ true ]]; do
        printf "%-19s %40s : " "$prompt" "[$default]"    
        read input

        input=${input:-$default}

        if [[ $input =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,31}[a-zA-Z0-9]$ ]]; then 
            READ_VALUE=$input.$DEFAULT_DOMAIN
            return 0
        elif [[ $input =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,31}[a-zA-Z0-9]\.[a-zA-Z0-9][a-zA-Z0-9-]{0,31}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then 
            READ_VALUE=$input
            return 0
        else
            printf "\n  *** A valid domain is required [$input] ***\n"
            continue
        fi
    done
}

# Prompt user and get a valid security zone
function Read_Security_Zone() {
    local prompt=$1
    local default=$2
    local input

    while [[ true ]]; do
        printf "%-49s %10s : " "$prompt" "[$default]"
        read input
        input=${input:-${default}}
        input=${input:0:1}
        input=${input^^}
        
        case $input in
            "S" | "SECURE")
                READ_VALUE="SECURE"
                return 0
                ;; 
            "P" | "PUBLIC")
                READ_VALUE="PUBLIC"
                return 0
                ;;
            "D" | "DMZ")
                READ_VALUE="DMZ"
                return 0
                ;;   
            "I" | "INTERNAL")
                READ_VALUE="INTERNAL"
                return 0
                ;;                       
            *)
                printf "\n *** Invalid input ***\n\n"
                continue
                ;; 
        esac
    done
}

# Prompt user with a default value, return "Y" or "N"
function Ask_Confirm() {
    local prompt=$1
    local default=$2
    local choice
    local input

    while [[ true ]]; do
        case $default in
            "Y")
                printf "\n%49s %10s : " "$prompt" "[Y/n]"
                ;;
            "N")
                printf "\n%49s %10s : " "$prompt" "[y/N]"
                ;;
            *)
                printf "\n%49s %10s : " "$prompt" "[Yes/No]"
                default=""
                ;;
        esac

        read input
        input=${input:-$default}
        input=${input^^}

        case $input in
            "Y" | "YES")
                return 0
                ;;
            "N" | "NO")
                return 1
                ;;
            *)
                printf "\n%60s\n" "*** Answer must be \"yes\" or \"no\"!"
                ;;
        esac
    done

    return 1
}

# Prompt user with a default value, return "Y" or "N"
function Inquiry() {
    local prompt=$1
    local default=$2
    local choice
    local input

    if [[ $default == "Y" ]]; then
        choice="[Y/n]"
    else
        choice="[y/N]"
    fi

    printf "%-53s %6s : " "$prompt" "$choice"
    read input
    input=${input:-$default}
    input=${input^^}

    if [[ $input == "Y" ]] || [[ $input == "YES" ]]; then
        return 0
    else
        return 1
    fi
}

# Change one line of conf file
function Update_Conf() {
    if sudo test -f $3; then
        sudo sed -i "\~$1~d" $3 #&> /dev/null
    fi
    echo "$2" | sudo tee -a $3 &> /dev/null

    return 0
}

# function:    Ftp_Download_File
function Ftp_Download_File() {
    local SRC_PATH=$1
    local DEST_FILE=$2

    sudo curl -fsSL -u creeksidenetworks:Good2Great $SRC_PATH -o $DEST_FILE

    if [[ ! -f $DEST_FILE ]]; then
        printf "\n *** Download failed, exit now\n\n"
        exit 
    fi
}

# Add a command to the configuration script
function Cfg_Cmd() {

#    if [[ $DEBUG_ON == "Y" ]]; then 
        echo "${Green}    >>> CFG-CMD: $1${Reset}"
#    fi

    echo "$1" | sudo tee -a $CREEKSIDE_CFG_SCRIPT &> /dev/null

    if [[ $ROUTER_TYPE == "EdgeRouter" ]]; then
        if ! eval "$ROUTER_CFGCMD $1"; then 
            printf "\n${Green}      >>> CFG ERROR: %s\n\n${Reset}"  "$1"
        fi
    fi

    return 0
}

# Add a comments to the configuration script and print out on console
function Cfg_Comment() {
    echo -e "$1"
    echo "echo -e \"$1\"" | sudo tee -a $CREEKSIDE_CFG_SCRIPT &> /dev/null
}

# Initiate a configuration
function Cfg_Initiate() {

    TS=$(date +"%Y-%m-%d %T %Z")
    echo -e "#!/bin/vbash\n# Creekside configration scripts\n# $TS\n"  | sudo tee $CREEKSIDE_CFG_SCRIPT &> /dev/null
    
    if [[ $ROUTER_TYPE == "EdgeRouter" ]]; then
        eval "$ROUTER_CFGCMD begin"
    else
        Cfg_Cmd "source /opt/vyatta/etc/functions/script-template"
        Cfg_Cmd "configure"
    fi

    return 0
}

# VyOS Finish configuration
function VyOS_Cfg_Finalize() {
    local change_saved="1"

    echo ""
    if Ask_Confirm " *** Show configurations scripts?" "N"; then
        printf "\n ***  Configurations scripts generated by Creekside ***\n\n"
        cat $CREEKSIDE_CFG_SCRIPT | more
    fi

    if Ask_Confirm "   *** Commit changes?"; then
        Cfg_Cmd "commit"

        if Ask_Confirm "   *** Save changes?"; then
            Cfg_Cmd "save"
            change_saved="0"
        fi

        printf  "\n ----------------- Router intialization started  ---------------------\n\n"

        sudo chmod +x $CREEKSIDE_CFG_SCRIPT
        sg vyattacfg -c $CREEKSIDE_CFG_SCRIPT

        return $change_saved        # return TRUE if changes are commited
    else
        return 1
    fi
}

# EdgeOS Finish configuration
function EdgeRouter_Cfg_Finalize() {

    echo ""
    if Ask_Confirm " *** Show configurations?" "N"; then
        printf "\n ***  Configurations generated by Creekside ***\n\n"
        $ROUTER_CFGCMD show
    fi

    if Ask_Confirm "   *** Commit changes?"; then
        printf  "\n ----------------- Router intialization started  ---------------------\n\n"
        $ROUTER_CFGCMD commit
 
        if Ask_Confirm "   *** Save changes?"; then
            $ROUTER_CFGCMD save
            return 0        # return TRUE if changes are commited
        fi
    else
        $ROUTER_CFGCMD discard
    fi

    $ROUTER_CFGCMD end
    return 1
}

# Finish configuration
function Cfg_Finalize() {
    if [[ $ROUTER_TYPE == "EdgeRouter" ]]; then
        EdgeRouter_Cfg_Finalize
    else
        VyOS_Cfg_Finalize
    fi

    return $?
}

# Inquiry install options for router initialization
function Inquiry_Router_Cfg_Options() {
    local domain

    # disable all zone policy by default
    ZONE_POLICY_PUBLIC="N"
    ZONE_POLICY_INTERNAL="N"
    ZONE_POLICY_DMZ="N"
    ZONE_POLICY_SECURE="N"

    # Obtain location information from current internet IP address
    printf  "\n o Inquire Geology information\n"

    # get current name servers
    i="0"
    while read -r field1 server_ip reminder; do
        if [[ $field1 == "nameserver" ]]; then
            DNS_SERVER[$i]=$server_ip
            i=$((i + 1))
        fi
    done  < <(cat /etc/resolv.conf)    

    if [[ ${DNS_SERVER[0]} == "" ]]; then
        # dns name servers are not configured, set up a tempo one
        echo -e "\nnameserver 1.1.1.1\nnameserver 223.5.5.5" | sudo tee -a /etc/resolv.conf &> /dev/null
    fi

    GEOINFO=$(curl -s http://ip-api.com/json/)

    if [[ -z $GEOINFO ]]; then
        echo -e "\n**** Can not retrieve geometry infomration, use China as default\n"
        COUNTRY="CN";
        TIMEZONE="Asia/Shanghai"
    else
        COUNTRY=$(echo $GEOINFO | grep -o "\"countryCode\":.*" | cut -d , -f 1 | cut -d : -f 2 | tr -d \")
        TIMEZONE=$(echo $GEOINFO | grep -o "\"timezone\":.*" | cut -d , -f 1 | cut -d : -f 2 | tr -d \")
        ISP=$(echo $GEOINFO | grep -o "\"isp\":.*" | cut -d , -f 1 | cut -d : -f 2 | tr -d \")
    fi

    # collect inputs
    while [[ true ]]; do
        printf "\n o Collect required information\n"
        printf "   - Router\n"
        printf "%-28s %31s : " "     > ID (1-254)" "[$LOCAL_ID]" 
        read INPUT
        INPUT=${INPUT:-$LOCAL_ID}

        if [[ $INPUT == "" ]] || [[ $INPUT -lt 1 ]] || [[ $INPUT -gt 254 ]]; then
            printf "\n   *** Router ID must be in the range of 1-254\n\n"
            continue
        else
            LOCAL_ID=$INPUT
        fi
        
        Read_Hostname "     > Hostname" "$ROUTER_HOSTNAME"
        ROUTER_HOSTNAME=$READ_VALUE

        host=${ROUTER_HOSTNAME%%.*}
        domain=${ROUTER_HOSTNAME#*.}

        if [[ $WANIF_NUM -gt 1 ]]; then
            printf  "\n   - WAN interface(s) domain name\n"
            index=0
            for(( i=0; i<$NETIF_INDX; i++)) do
                if [[ ${NETIF_MODE[$i]} == "wan" ]]; then 
                    if [[ $index == "0" ]]; then
                        DEFAULT=${NETIF_HOST[0]:-$ROUTER_HOSTNAME}
                    else
                        DEFAULT=${NETIF_HOST[$i]:-$host$index.$domain}
                    fi
                    Address=${NETIF_ADDR[$i]}

                    Read_Hostname "     > ${NETIF_NAME[$i]}" "$DEFAULT"
                    NETIF_HOST[$i]=$READ_VALUE
                    # save WAN_FQDN for vpn server
                    WAN_FQDN[$index]=$READ_VALUE

                    NETIF_ZONE[$i]="PUBLIC"

                    index=$((index + 1))
                fi
            done

            DDNS_WEBCHECK="N"
        else
            # only one internet interface, use host name
            for(( i=0; i<$NETIF_INDX; i++)) do
                if [[ ${NETIF_MODE[$i]} == "wan" ]]; then 
                    NETIF_HOST[$i]=$ROUTER_HOSTNAME
                    # save WAN_FQDN for vpn server
                    WAN_FQDN[$index]=$ROUTER_HOSTNAME
                    NETIF_ZONE[$i]="PUBLIC"
                    break
                fi
            done

            DDNS_WEBCHECK="Y"
        fi

        printf  "\n   - Security zones (Public/Internal/Secure/DMZ)\n"
        index=0
        for(( i=0; i<$NETIF_INDX; i++)) do
            if [[ ${NETIF_ADDR[$i]} == "-" ]]; then continue; fi

            if [[ ${NETIF_MODE[$i]} == "lan" ]] || [[ ${NETIF_MODE[$i]} == "wan" ]]; then
                if  [[ ${NETIF_VLAN[$i]} == "253" ]]; then
                    default_zone=${NETIF_ZONE[$i]:-"DMZ"}
                else
                    default_zone=${NETIF_ZONE[$i]:-"INTERNAL"}
                fi

                QUESTION=$(printf "     > %-8s - %-18s" ${NETIF_NAME[$i]} ${NETIF_ADDR[$i]})
                Read_Security_Zone "$QUESTION" $default_zone
                NETIF_ZONE[$i]=$READ_VALUE

                case ${NETIF_ZONE[$i]} in
                    "PUBLIC")
                        ZONE_POLICY_PUBLIC="Y"
                        ;;
                    "SECURE")
                        ZONE_POLICY_SECURE="Y"
                        ;;
                    "DMZ")
                        ZONE_POLICY_DMZ="Y"
                        ;;
                    "INTERNAL")
                        ZONE_POLICY_INTERNAL="Y"
                        ;;
                    *)
                        printf "\n *** Invalid security zone ' ${NETIF_ZONE[$i]}' ***\n\n"
                        exit 1
                        ;;
                esac
            fi
        done


        printf  "\n   - Enable DHCP server\n"
        index=0
        for(( i=0; i<$NETIF_INDX; i++)) do
            NETIF_DHCP[$i]=${NETIF_DHCP[$i]:-"N"}
            if [[ ${NETIF_ADDR[$i]} == "-" ]]; then continue; fi

            if [[ ${NETIF_MODE[$i]} == "lan" ]]; then
                case ${NETIF_ZONE[$i]} in
                    "SECURE" | "DMZ" | "INTERNAL")
                        QUESTION=$(printf "     > %-8s - %-18s" ${NETIF_NAME[$i]} ${NETIF_ADDR[$i]})
                        if Inquiry "$QUESTION" "${NETIF_DHCP[$i]}"; then
                            NETIF_DHCP[$i]="Y"
                        else
                            NETIF_DHCP[$i]="N"
                        fi
                        ;;
                    *)
                        continue
                        ;;
                esac
            fi
        done

        # Compatibility with old scripts
        INSTALL_WG0="Y"
        ZONE_POLICY_INTERNAL="Y"  # wg0 is in office zone by default

        printf  "\n   - Regional information\n"
        printf  "%-34s %25s : " "     > Country code" "[$COUNTRY]"
        read INPUT
        COUNTRY=${INPUT:-$COUNTRY}
        COUNTRY=${COUNTRY^^}

        if [[ $COUNTRY == "CN" ]]; then
            TIMEZONE="Asia/Shanghai"
            DNS_SERVER[0]=$CHINA_DNS1
            DNS_SERVER[1]=$CHINA_DNS2
            DNS_SERVER[2]=$CHINA_DNS3
            DNS_SERVER[3]=""
        else
            DNS_SERVER[0]=$GLOBAL_DNS
            DNS_SERVER[1]=$GLOBAL_DNS2
            DNS_SERVER[2]=$GLOBAL_DNS3
            DNS_SERVER[3]=""        
        fi

        printf  "%-24s %35s : " "     > Timezone" "[$TIMEZONE]"
        read INPUT
        TIMEZONE=${INPUT:-$TIMEZONE}


        printf  "\n   - DNS servers ('-' to delete)\n"
        for ((i=0; i<3; i++)) do
            printf "%-42s %17s : " "     > DNS.$i" "[${DNS_SERVER[$i]}]"
            read input
            input=${input:-${DNS_SERVER[$i]}}
            if [[ $input == "-" ]]; then
                if [[ $i == "0" ]]; then 
                    printf "  *** At lease one DNS server is required!\n"
                    continue;
                else
                    DNS_SERVER[$i]=""
                    break
                fi
            elif Valid_IP $input; then
                DNS_SERVER[$i]=$input
            else
                printf "  *** A valid IP address is rquired!\n"
                continue
            fi 
        done

        echo ""
        if  Inquiry "   - Enable internal DNS server?" "$LOCAL_NAMESERVER_ENABLED"; then
            LOCAL_NAMESERVER_ENABLED="Y"
            Read_Domain "     > Domain" "$LOCAL_DOMAIN"
            LOCAL_DOMAIN=$READ_VALUE
            Read_IP     "     > Name-server IP" "$LOCAL_NS_ADDR"
            LOCAL_NS_ADDR=$READ_VALUE
            if  Inquiry "     > Is it an IPA server?" "Y"; then
                IPA_SERVER_IP=$LOCAL_NS_ADDR
                IPA_HOSTNAME=${IPA_HOSTNAME:-"ipa"}
                Read_Hostname "       ~ Host name" "$IPA_HOSTNAME"
                IPA_HOSTNAME=${READ_VALUE%%.*}  #obtain host name by stripping
                IPA_DOMAIN=$LOCAL_DOMAIN
                IPA_ENABLED="Y"
            fi
        else
            LOCAL_NAMESERVER_ENABLED="N"
        fi

        echo ""
        VPN_SERVER_ENABLED=${VPN_SERVER_ENABLED:-"N"}
        if  Inquiry "   - Enable external VPN server?" "$VPN_SERVER_ENABLED"; then
            VPN_SERVER_ENABLED="Y"

            Read_IP     "     > Server address" "$VPN_SERVER_ADDR"
            VPN_SERVER_ADDR=$READ_VALUE

            ROADWARRIOR_POOL[0]=${ROADWARRIOR_POOL[0]:-"10.255.240.0"}
            VIRTUAL_IP[0]=$(echo ${ROADWARRIOR_POOL[0]} | cut -d . -f 1)
            VIRTUAL_IP[1]=$(echo ${ROADWARRIOR_POOL[0]} | cut -d . -f 2)
            VIRTUAL_IP[2]=$(echo ${ROADWARRIOR_POOL[0]} | cut -d . -f 3)

            printf "     > Virtual IP for roadwarriors ('-' to end)\n"
            for((i=0; i<4; i++)) do            
                ROADWARRIOR_POOL[$i]=""
                if ! Read_IP_Pool24 "        Virtual IP" "${VIRTUAL_IP[0]}.${VIRTUAL_IP[1]}.${VIRTUAL_IP[2]}.0"; then
                    break;
                fi
                ROADWARRIOR_POOL[$i]=$READ_VALUE

                VIRTUAL_IP[0]=$(echo ${ROADWARRIOR_POOL[$i]} | cut -d . -f 1)
                VIRTUAL_IP[1]=$(echo ${ROADWARRIOR_POOL[$i]} | cut -d . -f 2)
                VIRTUAL_IP[2]=$(echo ${ROADWARRIOR_POOL[$i]} | cut -d . -f 3)
                VIRTUAL_IP[2]=$((${VIRTUAL_IP[2]} + 1))
            done
        else
            VPN_SERVER_ENABLED="N"
        fi

        printf  "\n   - Administrators\n"
        printf  "%-34s %25s : " "     > admin's password" "[$ADMIN_PASSWORD]"
        read INPUT
        ADMIN_PASSWORD=${INPUT:-$ADMIN_PASSWORD}

        printf  "%-34s %25s : " "     > jtong's password" "[$JTONG_PASSWORD]"
        read INPUT
        JTONG_PASSWORD=${INPUT:-$JTONG_PASSWORD}

        if  Inquiry "     > Disable SSH password login?" "$DISABLE_SSH_PASSWD"; then
            DISABLE_SSH_PASSWD="Y"
        else
            DISABLE_SSH_PASSWD="N"
        fi

        if  Inquiry "     > Prohibit public access to router's web page?" "$DISABLE_WEB_ACCESS"; then
            DISABLE_WEB_ACCESS="Y"
        else
            DISABLE_WEB_ACCESS="N"
        fi

        echo ""
        if  Ask_Confirm "   >>> Do you confirm?"; then
            return 0
        elif Ask_Confirm "   >>> Return to main menu?"; then
            return 1
        fi
    done     
}

# ****************************************************************************
# Upload site conf file to system ftp server
# Usage:
#      VyOS_Initialization
# ****************************************************************************
function Upload_Site_Conf() {
    LOCAL_RSAPUB=$(sudo cat /config/ipsec.d/rsa-keys/localhost.pub)
    echo "$LOCAL_ID ${WAN_FQDN[0]} $LOCAL_WG0_PORT $LOCAL_WG0_IP $LOCAL_WG0_PUB $LOCAL_RSAPUB" | sudo tee /config/creekside/conf/$ROUTER_HOSTNAME.site &> /dev/null
    sudo curl -fsSL -u creeksidenetworks:Good2Great ftp://$FTP_SERVER/sites/$ROUTER_HOSTNAME.site -T /config/creekside/conf/$ROUTER_HOSTNAME.site
}

# ****************************************************************************
# EdgeOS Install WireGuard
# Usage:
#      EdgeOS_Install_WireGuard
# ****************************************************************************
function Download_Files() {
    printf "\n o Download utilities & scripts\n"

    if [[ $ROUTER_TYPE == "EdgeRouter" ]]; then
        printf   "   - WireGuard deb file\n"
        Ftp_Download_File ftp://$FTP_SERVER/wireguard/${UBNT_HWID}-v2.deb $WIREGUARD_DEB_V2 
  
        if [[ $(dpkg-query -W -f='${Status}' wireguard | awk '{print $2}') != 'ok' ]]; then
            printf   "   - Install WireGuard release ${WIREGUARD_RELEASE}\n"
            sudo dpkg -i $WIREGUARD_DEB_V2 &> /dev/null
        fi
    fi

    printf   "   - Download WireGuard scripts\n"
    Ftp_Download_File ftp://$FTP_SERVER/scripts/wireguard-bringup.sh        $WIREGUARD_BRINGUP_SCRIPTS 
    Ftp_Download_File ftp://$FTP_SERVER/scripts/wireguard-update.sh         $WIREGUARD_UPDATE_SCRIPTS 
    sudo chmod +x $WIREGUARD_BRINGUP_SCRIPTS
    sudo chmod +x $WIREGUARD_UPDATE_SCRIPTS

    printf   "   - Download SDWAN scripts & conf files\n"
    Ftp_Download_File ftp://$FTP_SERVER/scripts/sdwan-update.sh  $SDWAN_UPDATE_SCRIPTS
    sudo chmod +x $SDWAN_UPDATE_SCRIPTS

    Ftp_Download_File ftp://$FTP_SERVER/dnsmasq/dnsmasq_gfwlist_ipset.conf $DNSMASQ_GFW_CONF
    Ftp_Download_File ftp://$FTP_SERVER/dnsmasq/dnsmasq_custom_ipset.conf  $DNSMASQ_CUSTOM_CONF
    Ftp_Download_File ftp://$FTP_SERVER/sdwan/sdwan-servers.conf           $SDWAN_CONF_FILE

    printf   "   - Speet test python scripts\n"
    Ftp_Download_File ftp://$FTP_SERVER/scripts/speedtest.py  $SPEEDTEST_SCRIPTS 
    sudo chmod +x $SPEEDTEST_SCRIPTS 
}


# ****************************************************************************
# Configuration static router, dnat and ospf SR-MAP for internal VPN server
# Usage:
#      Add_External_VPN_Server
# ****************************************************************************
Add_External_VPN_Server() {
    local i=0

    if [[ $VPN_SERVER_ENABLED == "Y" ]]; then
        Cfg_Comment "\n o Configure External VPN server"
        printf   "   - Enable VPN server [$VPN_SERVER_ADDR]\n"

        Cfg_Cmd "set firewall group address-group ADDR-VPN-SERVERS address $VPN_SERVER_ADDR"
        printf   "   - Setup routes for roadwarrior VPN clients\n"

        while [[ ${ROADWARRIOR_POOL[$i]} != "" ]]; do
            Cfg_Cmd "set protocols static route ${ROADWARRIOR_POOL[$i]}/24 next-hop $VPN_SERVER_ADDR distance 10"
            Cfg_Cmd "set policy prefix-list ROADWARRIOR rule 1$i action permit"
            Cfg_Cmd "set policy prefix-list ROADWARRIOR rule 1$i prefix ${ROADWARRIOR_POOL[$i]}/24"
            i=$((i+1))
        done

        Cfg_Cmd "set policy route-map SR-MAP rule 10 action permit"
        Cfg_Cmd "set policy route-map SR-MAP rule 10 match ip address prefix-list ROADWARRIOR"

        Cfg_Cmd "set protocols ospf parameters router-id 0.0.0.$LOCAL_ID"
        Cfg_Cmd "set protocols ospf passive-interface default"
        Cfg_Cmd "set protocols ospf redistribute static metric-type 2"
        Cfg_Cmd "set protocols ospf redistribute static route-map SR-MAP"
    fi
}

# ****************************************************************************
# Create default zone base firewall, only internet and local zones are created
# Usage:
#      Create_Default_Firewall
# ****************************************************************************
function Create_Default_Firewall() {

    Cfg_Comment "\n o Setup default firewall"
    Cfg_Cmd "set firewall all-ping 'enable'"

    Cfg_Cmd "set firewall group address-group ADDR-GRE-DUMMY description 'GRE over IPSec local outside addr'"

	Cfg_Cmd "set firewall group address-group ADDR-AD-SERVERS description 'Windows ADservers'"
	Cfg_Cmd "set firewall group address-group ADDR-GIT-SERVES description 'GIT servers'"
	Cfg_Cmd "set firewall group address-group ADDR-IPA-SERVERS description 'IPA servers'"
	Cfg_Cmd "set firewall group address-group ADDR-IT-ADMIN description 'IT admins via WireGuard'"
	Cfg_Cmd "set firewall group address-group ADDR-SECSRV-EXEMPTED description 'secure servers allowed internet access'"

	Cfg_Cmd "set firewall group address-group ADDR-VPN-MANAGER description 'corporate managers'"
	Cfg_Cmd "set firewall group address-group ADDR-VPN-SERVERS description 'VPN servers'"
	Cfg_Cmd "set firewall group address-group ADDR-VPN-STAFF description 'staff engineers'"
	Cfg_Cmd "set firewall group address-group ADDR-VPN-USER description 'vpn users'"

	Cfg_Cmd "set firewall group network-group NETS-PRIVATE description 'private networks'"
	Cfg_Cmd "set firewall group network-group NETS-PRIVATE network '10.0.0.0/8'"
	Cfg_Cmd "set firewall group network-group NETS-PRIVATE network '172.16.0.0/12'"
	Cfg_Cmd "set firewall group network-group NETS-PRIVATE network '192.168.0.0/16'"

	Cfg_Cmd "set firewall group network-group NETS-SECURE-ZONE description 'Secure zone networks'"

	Cfg_Cmd "set firewall group port-group PORTS-MGT description 'management ports'"
	Cfg_Cmd "set firewall group port-group PORTS-MGT port '22'"

	Cfg_Cmd "set firewall group port-group PORTS-WIREGUARD description 'WireGuard ports'"
	Cfg_Cmd "set firewall group port-group PORTS-WIREGUARD port '52800'"
	Cfg_Cmd "set firewall group port-group PORTS-WIREGUARD port '52801'"
	
    Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP description 'Windows AD TCP ports'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP port '88'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP port '135'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP port '139'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP port '389'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP port '636'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP port '3268-3269'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP port '53'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP port '445'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-TCP port '464'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-UDP description 'Windows AD UDP ports'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-UDP port '88'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-UDP port '123'"
    Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-UDP port '389'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-UDP port '53'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-UDP port '1812'"
	Cfg_Cmd "set firewall group port-group PORTS-AD-SERVERS-UDP port '1813'"

	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-TCP description 'ipa client/server tcp ports'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-TCP port '80'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-TCP port '88'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-TCP port '389'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-TCP port '464'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-TCP port '636'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-TCP port '443'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-TCP port '53'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-TCP port '749'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-UDP description 'ipa client/server udp ports'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-UDP port '123'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-UDP port '464'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-UDP port '53'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-UDP port '88'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-UDP port '1812'"
	Cfg_Cmd "set firewall group port-group PORTS-IPA-SERVERS-UDP port '1813'"

	Cfg_Cmd "set firewall group port-group PORTS-REMOTE-DESKTOP description 'Remote desktop access port, vnc & RDP'"
	Cfg_Cmd "set firewall group port-group PORTS-REMOTE-DESKTOP port '3389'"
	Cfg_Cmd "set firewall group port-group PORTS-REMOTE-DESKTOP port '5900-5999'"

	Cfg_Cmd "set firewall group port-group PORT-GIT-SERVERS description 'GIT access ports'"
	Cfg_Cmd "set firewall group port-group PORT-GIT-SERVERS port '80'"
	Cfg_Cmd "set firewall group port-group PORT-GIT-SERVERS port '443'"

	Cfg_Cmd "set firewall ipv6-receive-redirects 'disable'"
	Cfg_Cmd "set firewall ipv6-src-route 'disable'"
	Cfg_Cmd "set firewall ip-src-route 'disable'"
	Cfg_Cmd "set firewall log-martians 'enable'"

	Cfg_Cmd "set firewall name DEFAULT_ACCEPT default-action 'accept'"
	Cfg_Cmd "set firewall name DEFAULT_DROP default-action 'drop'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 1 action 'accept'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 1 log 'disable'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 2 action 'drop'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 2 log 'disable'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 2 state invalid 'enable'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 100 action 'accept'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 100 description 'allow IT Admins access anything'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 100 log 'disable'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 100 source group address-group 'ADDR-IT-ADMIN'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 110 action 'accept'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 110 description 'allow pings'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 110 icmp type-name 'echo-request'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 110 log 'disable'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 110 protocol 'icmp'"

	Cfg_Cmd "set firewall name DMZ_INTERNAL default-action 'drop'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL description 'dmz to internal'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 1 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 1 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2 action 'drop'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2 state invalid 'enable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 100 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 100 description 'allow IT Admins access anything'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 100 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 100 source group address-group 'ADDR-IT-ADMIN'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 110 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 110 description 'allow ping internal'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 110 icmp type-name 'echo-request'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 110 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 110 protocol 'icmp'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 1000 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 1000 description 'allow internal VPN users to access company resource'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 1000 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 1000 source group address-group 'ADDR-VPN-USER'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2030 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2030 description 'allow access IPA servers'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2030 destination group address-group 'ADDR-IPA-SERVERS'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2030 destination group port-group 'PORTS-IPA-SERVERS-TCP'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2030 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2030 protocol 'tcp'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2031 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2031 description 'allow access IPA servers'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2031 destination group address-group 'ADDR-IPA-SERVERS'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2031 destination group port-group 'PORTS-IPA-SERVERS-UDP'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2031 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2031 protocol 'udp'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2040 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2040 description 'allow access AD servers'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2040 destination group address-group 'ADDR-AD-SERVERS'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2040 destination group port-group 'PORTS-AD-SERVERS-TCP'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2040 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2040 protocol 'tcp'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2041 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2041 description 'allow access AD servers'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2041 destination group address-group 'ADDR-AD-SERVERS'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2041 destination group port-group 'PORTS-AD-SERVERS-UDP'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2041 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2041 protocol 'udp'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2050 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2050 description 'allow exempted server access internal'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2050 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_INTERNAL rule 2050 source group address-group 'ADDR-SECSRV-EXEMPTED'"

	Cfg_Cmd "set firewall name DMZ_LOCAL default-action 'drop'"
	Cfg_Cmd "set firewall name DMZ_LOCAL description 'dmz to router'"

	Cfg_Cmd "set firewall name DMZ_LOCAL rule 1 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 1 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 1 state related 'enable'"

	Cfg_Cmd "set firewall name DMZ_LOCAL rule 2 action 'drop'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 2 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 2 state invalid 'enable'"

	Cfg_Cmd "set firewall name DMZ_LOCAL rule 110 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 110 description 'allow ping internal'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 110 icmp type-name 'echo-request'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 110 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 110 protocol 'icmp'"

	Cfg_Cmd "set firewall name DMZ_LOCAL rule 120 action accept"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 120 description 'allow dns'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 120 log disable"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 120 protocol tcp_udp"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 120 destination port 53"

	Cfg_Cmd "set firewall name DMZ_LOCAL rule 130 action accept"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 130 description 'allow dhcp'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 130 log disable"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 130 protocol udp"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 130 destination port 67"

	Cfg_Cmd "set firewall name DMZ_LOCAL rule 140 action accept"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 140 description 'allow mDNS'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 140 log disable"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 140 protocol udp"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 140 destination port 5353"

	Cfg_Cmd "set firewall name DMZ_LOCAL rule 1000 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 1000 description 'allow VPN user to access router'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 1000 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_LOCAL rule 1000 source group address-group 'ADDR-VPN-USER'"

	Cfg_Cmd "set firewall name DMZ_SECURE default-action 'drop'"
	Cfg_Cmd "set firewall name DMZ_SECURE description 'dmz to secure'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 1 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 1 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 2 action 'drop'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 2 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 2 state invalid 'enable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 100 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 100 description 'allow IT Admins access anything'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 100 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 100 source group address-group 'ADDR-IT-ADMIN'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 110 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 110 description 'allow pings'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 110 icmp type-name 'echo-request'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 110 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 110 protocol 'icmp'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 1000 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 1000 description 'allow VPN managers to access secure resource'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 1000 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 1000 source group address-group 'ADDR-VPN-MANAGER'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 2000 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 2000 description 'allow full access to exempted servers'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 2000 destination group address-group 'ADDR-SECSRV-EXEMPTED'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 2000 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 3000 action 'accept'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 3000 description 'allow remote desktop access only'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 3000 destination group port-group 'PORTS-REMOTE-DESKTOP'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 3000 log 'disable'"
	Cfg_Cmd "set firewall name DMZ_SECURE rule 3000 protocol 'tcp'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE default-action 'drop'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE description 'internal to secure'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 1 action 'accept'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 1 log 'disable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2 action 'drop'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2 log 'disable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2 state invalid 'enable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 100 action 'accept'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 100 description 'allow IT Admins access anything'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 100 log 'disable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 100 source group address-group 'ADDR-IT-ADMIN'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 110 action 'accept'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 110 description 'allow pings'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 110 icmp type-name 'echo-request'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 110 log 'disable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 110 protocol 'icmp'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2000 action 'accept'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2000 description 'allow intra-secure zone traffic'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2000 destination group network-group 'NETS-SECURE-ZONE'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2000 log 'disable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2000 source group network-group 'NETS-SECURE-ZONE'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2010 action 'accept'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2010 description 'allow full access to exempted servers'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2010 destination group address-group 'ADDR-SECSRV-EXEMPTED'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 2010 log 'disable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 3000 action 'accept'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 3000 description 'allow remote desktop access only'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 3000 destination group port-group 'PORTS-REMOTE-DESKTOP'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 3000 log 'disable'"
	Cfg_Cmd "set firewall name INTERNAL_SECURE rule 3000 protocol 'tcp'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ default-action 'drop'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ description 'internet to internal'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 2 action 'drop'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 2 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 2 state invalid 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1000 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1000 description 'Allow Roadwarrior VPN traffic'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1000 destination group address-group 'ADDR-VPN-SERVERS'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1000 destination port '500,4500'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1000 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_DMZ rule 1000 protocol 'udp'"

	Cfg_Cmd "set firewall name PUBLIC_INTERNAL default-action 'drop'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL description 'internet to internal'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 2 action 'drop'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 2 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 2 state invalid 'enable'"
	
    Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 120 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 120 description 'allow GRE over IPSec'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 120 ipsec match-ipsec"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 120 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 120 destination group address-group ADDR-GRE-DUMMY"

	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1000 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1000 description 'Allow inside VPN server'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1000 destination group address-group 'ADDR-VPN-SERVERS'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1000 destination port '500,4500'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1000 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1000 protocol 'udp'"

	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1100 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1100 description 'Allow internal VPN users to access internal'"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1100 ipsec match-ipsec"
	Cfg_Cmd "set firewall name PUBLIC_INTERNAL rule 1100 log 'disable'"

	Cfg_Cmd "set firewall name PUBLIC_LOCAL default-action 'drop'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL description 'internet to router'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 2 action 'drop'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 2 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 2 state invalid 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 100 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 100 description 'allow remote management'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 100 destination group port-group 'PORTS-MGT'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 100 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 100 protocol 'tcp'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 110 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 110 description 'allow ping from PUBLIC'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 110 icmp type-name 'echo-request'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 110 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 110 protocol 'icmp'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 120 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 120 description 'allow GRE over IPSec'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 120 ipsec match-ipsec"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 120 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 120 destination group address-group ADDR-GRE-DUMMY"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1000 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1000 description 'ipsec-ike/nat'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1000 destination port '500,4500'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1000 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1000 protocol 'udp'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1001 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1001 description 'ipsec esp'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1001 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1001 protocol 'esp'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1002 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1002 description 'gre over ipsec'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1002 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1002 ipsec match-ipsec"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1002 protocol 'gre'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1003 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1003 description 'Allow IPSec traffic to access router'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1003 ipsec match-ipsec"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1003 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1010 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1010 description 'allow WireGuard'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1010 destination group port-group 'PORTS-WIREGUARD'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1010 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_LOCAL rule 1010 protocol 'udp'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE default-action 'drop'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE description 'internet to secure'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 2 action 'drop'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 2 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 2 state invalid 'enable'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1000 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1000 description 'Allow VPN managers to have full access'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1000 ipsec match-ipsec"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1000 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1000 source group address-group 'ADDR-VPN-MANAGER'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1001 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1001 description 'Allow VPN staff to access GIT servers'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1001 destination group address-group 'ADDR-GIT-SERVES'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1001 destination group port-group 'PORT-GIT-SERVERS'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1001 ipsec match-ipsec"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1001 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1001 protocol 'tcp'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1001 source group address-group 'ADDR-VPN-STAFF'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1002 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1002 description 'Allow VPN user to access remote-desktops'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1002 destination group port-group 'PORTS-REMOTE-DESKTOP'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1002 ipsec match-ipsec"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1002 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1002 source group address-group 'ADDR-VPN-USER'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1003 action 'accept'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1003 description 'allow full access to exempted servers'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1003 destination group address-group 'ADDR-SECSRV-EXEMPTED'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1003 ipsec match-ipsec"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1003 log 'disable'"
	Cfg_Cmd "set firewall name PUBLIC_SECURE rule 1003 source group address-group 'ADDR-VPN-USER'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL default-action 'drop'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL description 'secure to internal'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 1 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 1 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2 action 'drop'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2 state invalid 'enable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 110 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 110 description 'allow ping internal'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 110 icmp type-name 'echo-request'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 110 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 110 protocol 'icmp'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2000 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2000 description 'allow intra-secure zone traffic'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2000 destination group network-group 'NETS-SECURE-ZONE'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2000 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2000 source group network-group 'NETS-SECURE-ZONE'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2030 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2030 description 'allow access IPA servers'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2030 destination group address-group 'ADDR-IPA-SERVERS'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2030 destination group port-group 'PORTS-IPA-SERVERS-TCP'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2030 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2030 protocol 'tcp'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2031 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2031 description 'allow access IPA servers'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2031 destination group address-group 'ADDR-IPA-SERVERS'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2031 destination group port-group 'PORTS-IPA-SERVERS-UDP'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2031 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2031 protocol 'udp'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2040 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2040 description 'allow access AD servers'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2040 destination group address-group 'ADDR-AD-SERVERS'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2040 destination group port-group 'PORTS-AD-SERVERS-TCP'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2040 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2040 protocol 'tcp'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2041 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2041 description 'allow access AD servers'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2041 destination group address-group 'ADDR-AD-SERVERS'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2041 destination group port-group 'PORTS-AD-SERVERS-UDP'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2041 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2041 protocol 'udp'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2050 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2050 description 'allow exempted server access internal'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2050 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_INTERNAL rule 2050 source group address-group 'ADDR-SECSRV-EXEMPTED'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC default-action 'drop'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC description 'secure to internet'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 1 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 2 action 'drop'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 2 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 2 state invalid 'enable'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 123 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 123 description 'allow ntp'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 123 destination port '123'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 123 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 123 protocol 'udp'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 2000 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 2000 description 'allow exempted server access internet'"
	Cfg_Cmd "set firewall name SECURE_PUBLIC rule 2000 source group address-group 'ADDR-SECSRV-EXEMPTED'"

	Cfg_Cmd "set firewall name SECURE_DMZ default-action 'drop'"
	Cfg_Cmd "set firewall name SECURE_DMZ description 'secure to dmz'"
	Cfg_Cmd "set firewall name SECURE_DMZ rule 1 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_DMZ rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name SECURE_DMZ rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name SECURE_DMZ rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name SECURE_DMZ rule 2 action 'drop'"
	Cfg_Cmd "set firewall name SECURE_DMZ rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name SECURE_DMZ rule 2 log 'disable'"
	Cfg_Cmd "set firewall name SECURE_DMZ rule 2 state invalid 'enable'"
}

# ****************************************************************************
# Install Security Zones on VyOS/EdgeRouter
# Usage:
#      Create_Security_Zone
# ****************************************************************************
function Add_Zone_Policy_Public() {
    if [[ $ZONE_POLICY_PUBLIC != "Y" ]]; then
        return
    fi

    Cfg_Cmd "set zone-policy zone PUBLIC default-action drop"

    Cfg_Cmd "set zone-policy zone PUBLIC from LOCAL firewall name DEFAULT_ACCEPT"

    if [[ $ZONE_POLICY_INTERNAL == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone PUBLIC from INTERNAL firewall name DEFAULT_ACCEPT"
    fi

    if [[ $ZONE_POLICY_SECURE == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone PUBLIC from SECURE firewall name SECURE_PUBLIC"
    fi

    if [[ $ZONE_POLICY_DMZ == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone PUBLIC from DMZ firewall name DEFAULT_ACCEPT"
    fi
}

function Add_Zone_Policy_Internal() {
    if [[ $ZONE_POLICY_INTERNAL != "Y" ]]; then
        return
    fi

    Cfg_Cmd "set zone-policy zone INTERNAL default-action drop"

    Cfg_Cmd "set zone-policy zone INTERNAL from LOCAL firewall name DEFAULT_ACCEPT"

    if [[ $ZONE_POLICY_PUBLIC == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone INTERNAL from PUBLIC firewall name PUBLIC_INTERNAL"
    fi

    if [[ $ZONE_POLICY_SECURE == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone INTERNAL from SECURE firewall name SECURE_INTERNAL"
    fi

    if [[ $ZONE_POLICY_DMZ == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone INTERNAL from DMZ    firewall name DMZ_INTERNAL"
    fi
}

function Add_Zone_Policy_Secure() {
    if [[ $ZONE_POLICY_SECURE != "Y" ]]; then
        return
    fi

    Cfg_Cmd "set zone-policy zone SECURE default-action drop"

    Cfg_Cmd "set zone-policy zone SECURE from LOCAL firewall name DEFAULT_ACCEPT"

    if [[ $ZONE_POLICY_PUBLIC == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone SECURE from PUBLIC   firewall name PUBLIC_SECURE"
    fi

    if [[ $ZONE_POLICY_INTERNAL == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone SECURE from INTERNAL firewall name INTERNAL_SECURE"
    fi

    if [[ $ZONE_POLICY_DMZ == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone SECURE from DMZ      firewall name DMZ_SECURE"
    fi

}

function Add_Zone_Policy_DMZ() {
    if [[ $ZONE_POLICY_DMZ != "Y" ]]; then
        return
    fi

    Cfg_Cmd "set zone-policy zone DMZ default-action drop"

    Cfg_Cmd "set zone-policy zone DMZ from LOCAL firewall name DEFAULT_ACCEPT"

    if [[ $ZONE_POLICY_PUBLIC == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone DMZ from PUBLIC firewall name PUBLIC_DMZ"
    fi

    if [[ $ZONE_POLICY_INTERNAL == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone DMZ from INTERNAL firewall name DEFAULT_ACCEPT"
    fi

    if [[ $ZONE_POLICY_SECURE == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone DMZ from SECURE firewall name SECURE_DMZ"
    fi
}

function Add_Zone_Policy_Local() {
      # Create local zone
    Cfg_Cmd "set zone-policy zone LOCAL default-action drop"

    if [[ $ZONE_POLICY_PUBLIC == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone LOCAL from PUBLIC firewall name PUBLIC_LOCAL"
    fi

    if [[ $ZONE_POLICY_INTERNAL == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone LOCAL from INTERNAL firewall name DEFAULT_ACCEPT"
    fi

    if [[ $ZONE_POLICY_SECURE == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone LOCAL from SECURE firewall name DEFAULT_ACCEPT"
    fi

    if [[ $ZONE_POLICY_DMZ == "Y" ]]; then
        Cfg_Cmd "set zone-policy zone LOCAL from DMZ firewall name DMZ_LOCAL"
    fi

    Cfg_Cmd "set zone-policy zone LOCAL local-zone"

}
function Create_Security_Zone() {

    # Create local zone

    Add_Zone_Policy_Local

    if [[ $ZONE_POLICY_PUBLIC == "Y" ]]; then
        Add_Zone_Policy_Public
    fi

    if [[ $ZONE_POLICY_INTERNAL == "Y" ]]; then
        Add_Zone_Policy_Internal
    fi

    if [[ $ZONE_POLICY_SECURE == "Y" ]]; then
        Add_Zone_Policy_Secure
    fi

    if [[ $ZONE_POLICY_DMZ == "Y" ]]; then
        Add_Zone_Policy_DMZ
    fi
}

# ****************************************************************************
# Install WireGuard interfaces on VyOS/EdgeRouter
# Usage:
#      Install_WireGuard
# ****************************************************************************
Install_WireGuard() {



    Cfg_Comment "\n o Install WireGuard interfaces"
    sudo mkdir -p /config/auth/wireguard/{wg0,wg1}

    printf   "   - Setup interface wg0\n"
    if sudo test -f $WIREGUARD_CONF_FILE; then
        printf "%-60s : %s\n" "     > Found existing wireguard configuration" "$WIREGUARD_CONF_FILE"
        while read -r WG_INTF WG_ADDR WG_PORT WG_KEY REMINDER; do
            case $WG_INTF in
                "wg0")
                    printf "%-60s : %s\n" "      ~ Load wg0 private-key" "$WG_KEY"
                    LOCAL_WG0_KEY=$WG_KEY
                    LOCAL_WG0_IP=$WG_ADDR
                    LOCAL_WG0_PORT=$WG_PORT
                    ;;
                "wg1")
                    printf "%-60s : %s\n" "      ~ Load wg1 private-key" "$WG_KEY"
                    LOCAL_WG1_IP=$WG_ADDR
                    LOCAL_WG1_PORT=$WG_PORT
                    LOCAL_WG1_KEY=$WG_KEY
                    ;;
                *)
                    printf "%-60s : %s\n" "      ~ Ignore interface" "$WG_INTF"
                    ;;
            esac
        done  < $WIREGUARD_CONF_FILE
    elif sudo test -f $WG0_KEY_FILE; then
        printf "%-60s : %s\n" "     > Found existing key pair for wg0" "$WG0_KEY_FILE"
        LOCAL_WG0_KEY=$(sudo cat $WG0_KEY_FILE)
    else
        printf "%-60s : %s\n" "     > Generate key pair for wg0" "$WG0_KEY_FILE"
        LOCAL_WG0_KEY=$(sudo wg genkey | sudo tee $WG0_KEY_FILE)
        sudo cat $WG0_KEY_FILE | sudo wg pubkey | sudo tee $WG0_PUB_FILE  &> /dev/null
    fi

    LOCAL_WG0_PUB=$(echo $LOCAL_WG0_KEY | sudo wg pubkey | sudo tee $WG1_PUB_FILE)
    LOCAL_WG0_IP=${LOCAL_WG0_IP:-"10.255.255.$LOCAL_ID"}
    LOCAL_WG0_PORT=${LOCAL_WG0_PORT:-"52800"}
    printf "%-60s : %s\n" "       > Private key"    "$LOCAL_WG0_KEY"
    printf "%-60s : %s\n" "       > Public key"     "$LOCAL_WG0_PUB"
    printf "%-60s : %s\n" "       > Address"        "$LOCAL_WG0_IP/24"
    printf "%-60s : %s\n" "       > Listen-on"      "$LOCAL_WG0_PORT"
    wireguard_conf_line=$(printf "wg0 %-32s %-5s %-15s %s\n" "$LOCAL_WG0_IP" "$LOCAL_WG0_PORT" "$LOCAL_WG0_KEY")
    Update_Conf "wg0" "$wireguard_conf_line" $WIREGUARD_CONF_FILE

    printf   "   - Setup interface wg1\n"
    if ! sudo test -f $WG1_KEY_FILE; then
        printf "%-60s : %s\n" "     > Generate key pair for wg1" "$WG1_KEY_FILE"
        LOCAL_WG1_KEY=$(sudo wg genkey | sudo tee $WG1_KEY_FILE)
        sudo cat $WG1_KEY_FILE | sudo wg pubkey | sudo tee $WG1_PUB_FILE  &> /dev/null
    else
        printf "%-60s : %s\n" "     > Found existing key pair for wg1" "$WG1_KEY_FILE"
    fi

    LOCAL_WG1_KEY=$(sudo cat $WG1_KEY_FILE)
    LOCAL_WG1_PUB=$(echo $LOCAL_WG1_KEY | sudo wg pubkey | sudo tee $WG1_PUB_FILE)
    LOCAL_WG1_PRFX="10.$LOCAL_ID.249"
    LOCAL_WG1_IP=${LOCAL_WG1_IP:-"10.$LOCAL_ID.249"}
    LOCAL_WG1_PORT=${LOCAL_WG1_PORT:-"52801"}
    printf "%-60s : %s\n" "       > Private key"    "$LOCAL_WG1_KEY"
    printf "%-60s : %s\n" "       > Public key"     "$LOCAL_WG1_PUB"
    printf "%-60s : %s\n" "       > Address"        "$LOCAL_WG1_IP/24"
    printf "%-60s : %s\n" "       > Listen-on"      "$LOCAL_WG1_PORT"
    wireguard_conf_line=$(printf "wg1 %-32s %-5s %-15s %s\n" "$LOCAL_WG1_IP" "$LOCAL_WG1_PORT" "$LOCAL_WG1_KEY")
    Update_Conf "wg1" "$wireguard_conf_line" $WIREGUARD_CONF_FILE

    printf   "   - Update WireGuard peer conf file\n"
    # WireGuard peer configuration file
    # Insert default IT dialup

    WG1_PEER_IT_MGT_IP="$LOCAL_WG1_PRFX.201"
    wireguard_peer_line=$(printf "wg1 %-32s %-5s %-15s %s\n" "management_dialup" "$LOCAL_WG1_PORT" "$WG1_PEER_IT_MGT_IP" "$WIREGUARD_IT_PUB")
    Update_Conf $WIREGUARD_IT_PUB "$wireguard_peer_line" $WIREGUARD_PEER_FILE

    printf "%-60s : %s\n" "   - Firewall zone" "INTERNAL"
    Cfg_Cmd "set zone-policy zone INTERNAL interface wg0 &> /dev/null"
    Cfg_Cmd "set zone-policy zone INTERNAL interface wg1 &> /dev/null"

    printf   "   - Add task to update wireguard interface every 2 minutes\n"
    Cfg_Cmd "set system task-scheduler task update.wireguard interval 2m  &> /dev/null"
    Cfg_Cmd "set system task-scheduler task update.wireguard executable path $WIREGUARD_UPDATE_SCRIPTS  &> /dev/null"

    printf   "   - Now bringup WireGuard interfaces\n"
    $WIREGUARD_BRINGUP_SCRIPTS 
    $WIREGUARD_UPDATE_SCRIPTS 
}

# ****************************************************************************
# Configure Cloudflare DDNS
# Usage:
#      Cfg_Cloudflare_DDNS <interface>  <host name> <domain>
# ****************************************************************************
function VyOS_Cfg_Cloudflare_DDNS() {
    local interface=$1
    local host=$2
    local domain=$3
    
    Cfg_Cmd "delete service dns dynamic interface $interface &> /dev/null"
    Cfg_Cmd "set    service dns dynamic interface $interface service cloudflare host-name $host"
    Cfg_Cmd "set    service dns dynamic interface $interface service cloudflare login creeksidenetworks@gmail.com"
    Cfg_Cmd "set    service dns dynamic interface $interface service cloudflare password 3685187af3c3fe0ccd653a6b29b6475f999e8"
    Cfg_Cmd "set    service dns dynamic interface $interface service cloudflare protocol cloudflare"

    if [[ $DDNS_WEBCHECK == "Y" ]]; then
        Cfg_Cmd "set    service dns dynamic interface $interface use-web url checkip.dyndns.com"
        Cfg_Cmd "set    service dns dynamic interface $interface use-web skip \"IP Address: \""
    else
        Cfg_Cmd "delete service dns dynamic interface $interface use-web"
    fi

    return 0
}

# ****************************************************************************
# Configure WAN Interface
# Usage:
#      VyOS_Cfg_WAN_Interface
# ****************************************************************************
function VyOS_Cfg_WAN_Interface() {
    local i
    local PPPOE_DIST=10
    local index=0
    local dnat_rule_id=2530

    Cfg_Comment "\n o Configure WAN interfaces"
    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_MODE[$i]} == "wan" ]]; then
            printf "   - %s.%s\n" $index "${NETIF_NAME[$i]}"

            printf "%-60s : %s\n" "     > Firewall zone" "internet"
            # delete interface based firewall
            if  [[ ${NETIF_VLAN[$if_indx]} == "-" ]]; then
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_NAME[$i]} firewall &> /dev/null"
            else
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_NAME[$i]} vif ${NETIF_VLAN[$if_indx]} firewall &> /dev/null"
            fi

            Cfg_Cmd "set zone-policy zone PUBLIC interface ${NETIF_NAME[$i]}"

            # default route for internet (pppoe)
            if [[ ${NETIF_TYPE[$i]} == "pppoe" ]]; then
                printf "     > Add default route\n"
                Cfg_Cmd "set    protocols static interface-route 0.0.0.0/0 next-hop-interface ${NETIF_NAME[$i]} distance $PPPOE_DIST"
                PPPOE_DIST=$((PPPOE_DIST + 10))
            fi

            # tcp/mss
            printf "%-60s : %s\n" "     > TCP MSS" "$TCP_MSS"
            Cfg_Cmd "set firewall options interface ${NETIF_NAME[$i]} adjust-mss '$TCP_MSS' &> /dev/null"

            # NAT
            rule_id=$((i + 6000))
            printf "%-60s : %s\n" "     > Outbound Masquerade NAT" "rule #$rule_id"
            Cfg_Cmd "delete nat source rule $rule_id  &> /dev/null"
            Cfg_Cmd "set    nat source rule $rule_id outbound-interface ${NETIF_NAME[$i]}"
            Cfg_Cmd "set    nat source rule $rule_id translation address masquerade"
            Cfg_Cmd "set    nat source rule $rule_id description \"masquerade on WAN interface\""

            # DNAT for vpn server
            if [[ $VPN_SERVER_ENABLED == "Y" ]]; then
                printf "%-60s : %s\n" "     > Port forwarding for VPN server" "${NETIF_NAME[$i]}"
                Cfg_Cmd "delete nat destination rule $dnat_rule_id &> /dev/null"
                Cfg_Cmd "set nat destination rule $dnat_rule_id description 'dest nat for vpn server'"
                Cfg_Cmd "set nat destination rule $dnat_rule_id destination port '500,4500'"
                Cfg_Cmd "set nat destination rule $dnat_rule_id protocol udp"
                Cfg_Cmd "set nat destination rule $dnat_rule_id inbound-interface ${NETIF_NAME[$i]}"
                Cfg_Cmd "set nat destination rule $dnat_rule_id translation address '$VPN_SERVER_ADDR'"
                
                dnat_rule_id=$((dnat_rule_id+1))
            fi 

            # DDNS
            local hostname=${NETIF_HOST[$i]}
            local domain=${hostname#*.}                     # obtain domain by stripping 1st field
            if Check_Creekside_Managed_Domain $domain; then
                printf "%-60s : %s\n" "     > DDNS" "$hostname"
                VyOS_Cfg_Cloudflare_DDNS ${NETIF_NAME[$i]} $hostname $domain
            else
                printf "     > Not a creekside domain, bypass DDNS\n"
            fi
            index=$((index + 1))
        fi
    done

    return 0
}


# ****************************************************************************
# Configure LAN Interface
# Usage:
#      VyOS_Cfg_LAN_Interface
# ****************************************************************************
function VyOS_Cfg_LAN_Interface() {
    local i

    echo ""
    Cfg_Comment "\n o Configure LAN interfaces"

    printf "%s\n" "   - Enable DNS forwaring"
    Cfg_Cmd "delete service dns forwarding &> /dev/null"
    Cfg_Cmd "set service dns forwarding allow-from '0.0.0.0/0'"
    Cfg_Cmd "set service dns forwarding cache-size '10000'"

    if [[ $LOCAL_NAMESERVER_ENABLED == "Y" ]]; then
        Cfg_Cmd "set service dns forwarding domain $LOCAL_DOMAIN server $LOCAL_NS_ADDR"
    fi

    for ((i=0; i<3; i++)) do
        if [[ ${DNS_SERVER[$i]} != "" ]]; then
            Cfg_Cmd "set service dns forwarding name-server ${DNS_SERVER[$i]}"
        else
            break
        fi
    done

    printf "%s\n" "   - Add interface to zone policy"
    for ((i=0; i<$NETIF_INDX; i++)) do
        # assign proper security zone
        if [[ ${NETIF_MODE[$i]} == "lan" ]] && [[ ${NETIF_ADDR[$i]} != '-' ]]; then
            printf "%-42s %-17s : %s\n" "     > ${NETIF_NAME[$i]}" "${NETIF_ADDR[$i]}" "${NETIF_ZONE[$i]}"
            case ${NETIF_ZONE[$i]} in
                "SECURE" | "INTERNAL" | "PUBLIC" | "DMZ")
                    Cfg_Cmd "set zone-policy zone ${NETIF_ZONE[$i]} interface ${NETIF_NAME[$i]} "
                    ;;
                *)
                    printf "\n *** Invalid security zone [${NETIF_ZONE[$i]}] ***\n\n"
                    exit 1 
                    ;;
            esac
            # add to DNS forwaring list
            Address=${NETIF_ADDR[$i]}
            Cfg_Cmd "set service dns forwarding listen-address ${Address%/*}"
        fi
    done

    printf "%s\n" "   - Enable DHCP server"
    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_DHCP[$i]} == "Y" ]]; then
            prefix=$(echo ${NETIF_ADDR[$i]} | cut -d '.' -f 1-3)
            cidr=$(echo ${NETIF_ADDR[$i]} | cut -d '/' -f 2)

            printf "     > %-8s: %-18s\n" ${NETIF_NAME[$i]} "$prefix.0/24"            

            DHCP_NAME="DHCP-${NETIF_NAME[$i]}"
            DHCP_NAME=$(echo ${DHCP_NAME^^} | tr . -)
            DEFAULT_GATEWAY=$(echo ${NETIF_ADDR[$i]} | cut -d '/' -f 1)          

            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME authoritative"
            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME subnet $prefix.0/24 range 0 start $prefix.5"
            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME subnet $prefix.0/24 range 0 stop $prefix.199"
            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME subnet $prefix.0/24 default-router $DEFAULT_GATEWAY"
            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME subnet $prefix.0/24 dns-server $DEFAULT_GATEWAY"
        fi
    done
    # loopback interface
    LOOPBACK_IP=10.255.$LOCAL_ID.254
    printf "%-42s %-17s\n" "   - loopback" "$LOOPBACK_IP"
    Cfg_Cmd "set interfaces loopback lo address $LOOPBACK_IP/32"
    Cfg_Cmd "set service dns forwarding listen-address $LOOPBACK_IP"
    Cfg_Cmd "set firewall group address-group ADDR-GRE-DUMMY address $LOOPBACK_IP"

    return 0
}

function Generate_Bootup_Scripts() { 

local bootup_scripts_file=$1

    echo "#!/bin/bash
# VyOS boot up scripts
# By Creekside Networks LLC, 2021-2022

# Bringup WireGuard interfaces
$WIREGUARD_BRINGUP_SCRIPTS
$WIREGUARD_UPDATE_SCRIPTS

# Enable fqdn to be used in remote syslog
echo \"\\\$PreserveFQDN on\" | sudo tee /etc/rsyslog.d/remote.conf &> /dev/null
sudo service rsyslog restart
" | sudo tee $bootup_scripts_file
    sudo chmod +x $bootup_scripts_file


# Add creekside scripts to search path
echo "export PATH=\"/config/creekside/scripts:\$PATH\"" | sudo tee /etc/profile.d/creekside.sh

}

# ****************************************************************************
# Configure VyOS System options
# Usage:
#      VyOS_System_Options
# ****************************************************************************
function VyOS_System_Options() {
    Cfg_Comment "\n o System options\n"

    printf "   - Host name: [$ROUTER_HOSTNAME]\n"
    Cfg_Cmd "set    system host-name $ROUTER_HOSTNAME &> /dev/null"
    Cfg_Cmd "set    system domain-search domain $DEFAULT_DOMAIN  &> /dev/null"

    Cfg_Cmd "set    system login banner pre-login \"\nWelcome to $ROUTER_HOSTNAME\n\""
    Cfg_Cmd "set    system login banner post-login \"   - Proudly managed by Creekside Networks LLC\n\n\""

    printf "   - Update admins\n"
    Cfg_Cmd "set    system login user jtong authentication plaintext-password $JTONG_PASSWORD  &> /dev/null"
    Cfg_Cmd "set    system login user jtong authentication public-keys creeksidenetworks@gmail.com key AAAAB3NzaC1yc2EAAAADAQABAAABAQDHrPVbtdHf0aJeRu49fm/lLQPxopvvz6NZZqqGB+bcocZUW3Hw8bflhouTsJ+S4Z3v7L/F6mmZhXU1U3PqUXLVTE4eFMfnDjBlpOl0VDQoy9aT60C1Sreo469FB0XQQYS5CyIWW5C5rQQzgh1Ov8EaoXVGgW07GHUQCg/cmOBIgFvJym/Jmye4j2ALe641jnCE98yE4mPur7AWIs7n7W8DlvfEVp4pnreqKtlnfMqoOSTVl2v81gnp4H3lqGyjjK0Uku72GKUkAwZRD8BIxbA75oBEr3f6Klda2N88uwz4+3muLZpQParYQ+BhOTvldMMXnhqM9kHhvFZb21jTWV7p  &> /dev/null"
    Cfg_Cmd "set    system login user jtong authentication public-keys creeksidenetworks@gmail.com type ssh-rsa  &> /dev/null"

    Cfg_Cmd "set    system login user vyos  authentication plaintext-password $ADMIN_PASSWORD  &> /dev/null"

    Cfg_Cmd "set    system login user admin authentication plaintext-password $ADMIN_PASSWORD  &> /dev/null"
    Cfg_Cmd "set    system login user admin level admin  &> /dev/null"

    # update system name servers
    Cfg_Cmd "delete system name-server  &> /dev/null"
    i=0
    while [[ ${DNS_SERVER[$i]} != "" ]]; do
        Cfg_Cmd "set    system name-server ${DNS_SERVER[$i]} &> /dev/null"

        i=$((i + 1))
    done

    if [[ $DISABLE_SSH_PASSWD == "Y" ]]; then
        Cfg_Cmd "set    service ssh disable-password-authentication  &> /dev/null"
    else
        Cfg_Cmd "delete service ssh disable-password-authentication  &> /dev/null"
    fi

    Cfg_Cmd "set service ssh  client-keepalive-interval 15"
    
    printf "   - Timezone is [$TIMEZONE]\n"
    Cfg_Cmd "set    system time-zone $TIMEZONE  &> /dev/null"
    
    printf "   - Setup remote syslog server & enable fqdn\n"
    Cfg_Cmd "delete system syslog host &> /dev/null"
    Cfg_Cmd "set    system syslog host $NMS_SERVER facility all level err &> /dev/null"
    Cfg_Cmd "set    system syslog host $NMS_SERVER facility daemon level info &> /dev/null"

    # Enable ospf 
    printf "   - Enable OSPF\n"
    Cfg_Cmd "set    protocols ospf parameters router-id 0.0.0.$LOCAL_ID &> /dev/null"
    Cfg_Cmd "set    protocols ospf passive-interface default &> /dev/null"

    # Create IPSec RSA-keys
    # generate ipsec rsa-key if needed
    printf "   - IPSec RSA key\n"
    LOCAL_RSAPUB=""
    if sudo test -f /config/ipsec.d/rsa-keys/localhost.pub; then
        LOCAL_RSAPUB=$(sudo cat /config/ipsec.d/rsa-keys/localhost.pub)
    fi

    if [[ $LOCAL_RSAPUB =~ ^0sAw* ]]; then
        printf "     > Found existing key\n"
    else
        sudo rm -rf /config/ipsec.d/rsa-keys/
        sudo mkdir -p /config/ipsec.d/rsa-keys/
        $ROUTER_RUNCMD generate vpn rsa-key | grep 0sAw | sudo tee /config/ipsec.d/rsa-keys/localhost.pub
        echo ""
        LOCAL_RSAPUB=$(sudo cat /config/ipsec.d/rsa-keys/localhost.pub)
    fi

    Cfg_Cmd "set vpn rsa-keys local-key file /config/ipsec.d/rsa-keys/localhost.key"
    Cfg_Cmd "set vpn rsa-keys  rsa-key-name localhost-pub rsa-key $LOCAL_RSAPUB"
    
    echo -e     "   - Create boot up scripts"
    Generate_Bootup_Scripts "/config/scripts/vyos-postconfig-bootup.script"

    return 0
}


# ****************************************************************************
# VyOS initialization
# Usage:
#      VyOS_Initialization
# ****************************************************************************
function VyOS_Initialization() {

    printf    "\n  ----------------------- VyOS Initialization ------------------------\n"     
    if ! Inquiry_Router_Cfg_Options; then 
        printf  "\n ----------------- Router intialization cancelled --------------------\n\n"
        return 1
    fi

    # make configuration directories
    sudo mkdir -p $CREEKSIDE_ROOT/{conf,scripts,ipsec}

    Cfg_Initiate

    Create_Default_Firewall
    
    Download_Files
    
    Install_WireGuard

    VyOS_Cfg_WAN_Interface

    VyOS_Cfg_LAN_Interface

    Add_External_VPN_Server

    VyOS_System_Options

    Create_Security_Zone

    if Cfg_Finalize; then
        printf " o Save configurations\n"
        printf "   - Save [$LOCAL_CFG_FILE]\n"
        Save_Localhost_Cfg $LOCAL_CFG_FILE
        # upload site conf to ftp server
        printf "   - Update site info to ftp server\n"
        Upload_Site_Conf
    fi

    printf  "\n ----------------- Router intialization finished ---------------------\n\n"
    return 0
}



# ****************************************************************************
# Configure Cloudflare DDNS
# Usage:
#      EdgeOS_Cfg_Cloudflare_DDNS <interface>  <fqdn> <domain>
# ****************************************************************************
function EdgeOS_Cfg_Cloudflare_DDNS() {
    local interface=$1
    local host=$2
    local domain=$3
    
    Cfg_Cmd "delete service dns dynamic interface $interface service custom-cloudflare &> /dev/null"
    Cfg_Cmd "set    service dns dynamic interface $interface service custom-cloudflare host-name $host"
    Cfg_Cmd "set    service dns dynamic interface $interface service custom-cloudflare login creeksidenetworks@gmail.com"
    Cfg_Cmd "set    service dns dynamic interface $interface service custom-cloudflare options zone=$domain"
    Cfg_Cmd "set    service dns dynamic interface $interface service custom-cloudflare password 3685187af3c3fe0ccd653a6b29b6475f999e8"
    Cfg_Cmd "set    service dns dynamic interface $interface service custom-cloudflare protocol cloudflare"

    if [[ $DDNS_WEBCHECK == "Y" ]]; then
        Cfg_Cmd "set    service dns dynamic interface $interface web checkip.dyndns.com &> /dev/null"
    else
        Cfg_Cmd "delete service dns dynamic interface $interface web &> /dev/null"
    fi

    return 0
}

# ****************************************************************************
# Configure WAN Interface
# Usage:
#      EdgeOS_Cfg_WAN_Interface
# ****************************************************************************
function EdgeOS_Cfg_WAN_Interface() {
    local i
    local PPPOE_DIST=10
    local index=0
    local dnat_rule_id=2530

    printf "\n o Configure WAN interfaces\n"
    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_MODE[$i]} == "wan" ]]; then
            printf "   - %s.%s\n" $index "${NETIF_NAME[$i]}"

            printf "%-60s : %s\n" "     > Firewall zone" "internet"
            # delete interface based firewall
            if [[ ${NETIF_TYPE[$i]} == "pppoe" ]]; then
                # pppoe interface
                Cfg_Cmd "delete interfaces ethernet ${NETIF_BASE[$i]} pppoe ${NETIF_VLAN[$i]} firewall in &> /dev/null"
                Cfg_Cmd "delete interfaces ethernet ${NETIF_BASE[$i]} pppoe ${NETIF_VLAN[$i]} firewall local &> /dev/null"
            elif  [[ ${NETIF_VLAN[$if_indx]} == "-" ]]; then
                # ethernet/switch interface, w/o VLAN
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_NAME[$i]} firewall in &> /dev/null"
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_NAME[$i]} firewall local &> /dev/null"
            else
                # ethernet/switch interface, w VLAN
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_BASE[$i]} vif ${NETIF_VLAN[$i]} firewall in &> /dev/null"
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_BASE[$i]} vif ${NETIF_VLAN[$i]} firewall local &> /dev/null"
            fi

            Cfg_Cmd "set zone-policy zone PUBLIC interface ${NETIF_NAME[$i]}"

            # default route for internet (pppoe)
            if [[ ${NETIF_TYPE[$i]} == "pppoe" ]]; then
                printf "     > Add default route\n"
                Cfg_Cmd "set    protocols static interface-route 0.0.0.0/0 next-hop-interface ${NETIF_NAME[$i]} distance $PPPOE_DIST"
                PPPOE_DIST=$((PPPOE_DIST + 10))
            fi

            # NAT
            rule_id=$((i + 6000))
            printf "%-60s : %s\n" "     > Outbound Masquerade NAT" "rule #$rule_id"
            Cfg_Cmd "delete service nat rule $rule_id &> /dev/null"
            Cfg_Cmd "set    service nat rule $rule_id outbound-interface ${NETIF_NAME[$i]}"
            Cfg_Cmd "set    service nat rule $rule_id type masquerade"
            Cfg_Cmd "set    service nat rule $rule_id log disable"
            Cfg_Cmd "set    service nat rule $rule_id description \"masquerade on WAN [${NETIF_NAME[$i]}]\""

            # DNAT for vpn server
            if [[ $VPN_SERVER_ENABLED == "Y" ]]; then
                printf "%-60s : %s\n" "     > Port forwarding for VPN server" "${NETIF_NAME[$i]}"
                Cfg_Cmd "delete service nat rule $dnat_rule_id &> /dev/null"
                Cfg_Cmd "set service nat rule $dnat_rule_id description 'dnat for VPN server'"
                Cfg_Cmd "set service nat rule $dnat_rule_id destination port 500,4500"
                Cfg_Cmd "set service nat rule $dnat_rule_id inbound-interface ${NETIF_NAME[$i]}"
                Cfg_Cmd "set service nat rule $dnat_rule_id inside-address address $VPN_SERVER_ADDR"
                Cfg_Cmd "set service nat rule $dnat_rule_id log disable"
                Cfg_Cmd "set service nat rule $dnat_rule_id protocol udp"
                Cfg_Cmd "set service nat rule $dnat_rule_id type destination"

                dnat_rule_id=$((dnat_rule_id+1))
            fi

            # DDNS
            local hostname=${NETIF_HOST[$i]}
            local domain=${hostname#*.}                     # obtain domain by stripping 1st field
            if Check_Creekside_Managed_Domain $domain; then
                printf "%-60s : %s\n" "     > DDNS" "$hostname"
                EdgeOS_Cfg_Cloudflare_DDNS ${NETIF_NAME[$i]} $hostname $domain
            else
                printf "     > Not a creekside domain, bypass DDNS\n"
            fi
            index=$((index + 1))
        fi
    done

    return 0
}


# ****************************************************************************
# Configure LAN Interface
# Usage:
#      EdgeOS_Cfg_LAN_Interface
# ****************************************************************************
function EdgeOS_Cfg_LAN_Interface() {
    local i
    local unifi_ip

    printf "\n o Configure dns forwarding\n"

    printf "   - Enable DNSMASQ\n"
    Cfg_Cmd "set    service dhcp-server use-dnsmasq enable &> /dev/null"
    Cfg_Cmd "delete service dns forwarding except-interface &> /dev/null"
    
    printf "   - Configure upstream name servers\n"
    Cfg_Cmd "delete service dns forwarding name-server &> /dev/null"
    for ((i=0; i<3; i++)) do
        if [[ ${DNS_SERVER[$i]} != "" ]]; then
            Cfg_Cmd "set service dns forwarding name-server ${DNS_SERVER[$i]}"
        else
            break
        fi
    done

    if [[ $LOCAL_NAMESERVER_ENABLED == "Y" ]]; then
        printf "   - Set local name server for domain [$LOCAL_DOMAIN]\n"
        Cfg_Cmd "set service dns forwarding options server=/$LOCAL_DOMAIN/$LOCAL_NS_ADDR"
        # enable DNS domain search option
        Cfg_Cmd "set service dns forwarding options \"dhcp-option=option:domain-search,$LOCAL_DOMAIN\" &> /dev/null"
    fi
    
    # Update Unifi controllers
    unifi_ip=$(host -t A -W 15 $CREEKSIDE_UNIFI_FQDN | grep -o "address.*" | awk '{print $2}')
    if [[ $unifi_ip != "" ]]; then
        printf "   - Add CNMAE unif => unifi.creekside.network\n"
        Cfg_Cmd "set    service dns forwarding options cname=unifi,unifi.creekside.network &> /dev/null"
    fi

    printf "\n o Configure local interfaces\n"

    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_MODE[$i]} == "lan" ]] || [[ ${NETIF_MODE[$i]} == "local" ]]; then 
            # assign proper security zone
            NETIF_ZONE[$i]=${NETIF_ZONE[$i]:-"INTERNAL"}
            printf "%-42s %-17s : %s\n" "   - ${NETIF_NAME[$i]}" "${NETIF_ADDR[$i]}" "${NETIF_ZONE[$i]}"

            case ${NETIF_ZONE[$i]} in
                "SECURE" | "INTERNAL" | "DMZ" | "PUBLIC")
                    Cfg_Cmd "set zone-policy zone ${NETIF_ZONE[$i]} interface ${NETIF_NAME[$i]} "
                    ;;
                *)
                    printf "\n *** Invalid security zone ***\n\n"
                    exit 1 
                 ;;
            esac
        fi

        if [[ ${NETIF_MODE[$i]} == "lan" ]] && [[ ${NETIF_ADDR[$i]} != '-' ]]; then
            if  [[ ${NETIF_VLAN[$i]} == "-" ]]; then
                # ethernet/switch interface, w/o VLAN
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_NAME[$i]} firewall in name &> /dev/null"
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_NAME[$i]} firewall local &> /dev/null"
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_NAME[$i]} firewall out &> /dev/null"
            else
                # ethernet/switch interface, w VLAN
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_BASE[$i]} vif ${NETIF_VLAN[$i]} firewall in name &> /dev/null"
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_BASE[$i]} vif ${NETIF_VLAN[$i]} firewall local &> /dev/null"
                Cfg_Cmd "delete interfaces ${NETIF_TYPE[$i]} ${NETIF_BASE[$i]} vif ${NETIF_VLAN[$i]} firewall out &> /dev/null"
            fi

            # add to DNS forwaring list
            Address=${NETIF_ADDR[$i]}
            Cfg_Cmd "set service dns forwarding listen-on ${NETIF_NAME[$i]} &> /dev/null"
        fi
    done


    printf "%s\n" "   - Enable DHCP server"
    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_DHCP[$i]} == "Y" ]]; then
            prefix=$(echo ${NETIF_ADDR[$i]} | cut -d '.' -f 1-3)
            cidr=$(echo ${NETIF_ADDR[$i]} | cut -d '/' -f 2)

            printf "     > %-8s: %-18s\n" ${NETIF_NAME[$i]} "$prefix.0/24"  

            DHCP_NAME="DHCP-${NETIF_NAME[$i]}"
            DHCP_NAME=$(echo ${DHCP_NAME^^} | tr . -)       
            DEFAULT_GATEWAY=$(echo ${NETIF_ADDR[$i]} | cut -d '/' -f 1)          

            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME authoritative enable"
            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME subnet $prefix.0/$cidr lease 86400"
            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME subnet $prefix.0/$cidr start $prefix.5  stop $prefix.199"
            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME subnet $prefix.0/$cidr default-router $DEFAULT_GATEWAY"
            Cfg_Cmd "set service dhcp-server shared-network-name $DHCP_NAME subnet $prefix.0/$cidr dns-server $DEFAULT_GATEWAY"
        fi
    done

    # loopback interface
    LOOPBACK_IP=10.255.$LOCAL_ID.254
    printf "%-42s %-17s : %s\n" "   - loopback" "$LOOPBACK_IP" "-"
    Cfg_Cmd "set interfaces loopback lo address $LOOPBACK_IP/32 &> /dev/null"
    Cfg_Cmd "set service dns forwarding options listen-address=$LOOPBACK_IP &> /dev/null"

    return 0
}

# ****************************************************************************
# Configure VyOS System options
# Usage:
#      EdgeOS_System_Options
# ****************************************************************************
function EdgeOS_System_Options() {
    printf "\n o System options\n"

    printf "   - Host name: [$ROUTER_HOSTNAME]\n"
    Cfg_Cmd "set    system host-name $ROUTER_HOSTNAME &> /dev/null"
    Cfg_Cmd "set    system login banner pre-login \"\nWelcome to $ROUTER_HOSTNAME\n\""
    Cfg_Cmd "set    system login banner post-login \"   - Proudly managed by Creekside Networks LLC\n\n\""
    
    local domain=${ROUTER_HOSTNAME#*.} 
    Cfg_Cmd "delete system domain-name &> /dev/null"
    Cfg_Cmd "set    system domain-search domain $DEFAULT_DOMAIN  &> /dev/null"
    Cfg_Cmd "set    system domain-search domain $domain  &> /dev/null"

    printf "   - Update admins\n"
    Cfg_Cmd "set    system login user jtong authentication plaintext-password $JTONG_PASSWORD  &> /dev/null"
    Cfg_Cmd "set    system login user jtong authentication public-keys creeksidenetworks@gmail.com key AAAAB3NzaC1yc2EAAAADAQABAAABAQDHrPVbtdHf0aJeRu49fm/lLQPxopvvz6NZZqqGB+bcocZUW3Hw8bflhouTsJ+S4Z3v7L/F6mmZhXU1U3PqUXLVTE4eFMfnDjBlpOl0VDQoy9aT60C1Sreo469FB0XQQYS5CyIWW5C5rQQzgh1Ov8EaoXVGgW07GHUQCg/cmOBIgFvJym/Jmye4j2ALe641jnCE98yE4mPur7AWIs7n7W8DlvfEVp4pnreqKtlnfMqoOSTVl2v81gnp4H3lqGyjjK0Uku72GKUkAwZRD8BIxbA75oBEr3f6Klda2N88uwz4+3muLZpQParYQ+BhOTvldMMXnhqM9kHhvFZb21jTWV7p  &> /dev/null"
    Cfg_Cmd "set    system login user jtong authentication public-keys creeksidenetworks@gmail.com type ssh-rsa  &> /dev/null"
    Cfg_Cmd "set    system login user jtong level admin  &> /dev/null"

    Cfg_Cmd "set    system login user ubnt  authentication plaintext-password $ADMIN_PASSWORD  &> /dev/null"

    Cfg_Cmd "set    system login user admin authentication plaintext-password $ADMIN_PASSWORD  &> /dev/null"
    Cfg_Cmd "set    system login user admin level admin  &> /dev/null"

    # update system name servers
    Cfg_Cmd "delete system name-server  &> /dev/null"
    i=0
    while [[ ${DNS_SERVER[$i]} != "" ]]; do
        Cfg_Cmd "set    system name-server ${DNS_SERVER[$i]} &> /dev/null"

        i=$((i + 1))
    done

    if [[ $DISABLE_SSH_PASSWD == "Y" ]]; then
        Cfg_Cmd "set    service ssh disable-password-authentication  &> /dev/null"
    else
        Cfg_Cmd "delete service ssh disable-password-authentication  &> /dev/null"
    fi

    if [[ $DISABLE_WEB_ACCESS == "N" ]]; then
        Cfg_Cmd "set firewall group port-group PORTS-MGT port $GUI_PORT &> /dev/null"
    fi

    printf "   - Timezone is [$TIMEZONE]\n"
    Cfg_Cmd "set    system time-zone $TIMEZONE  &> /dev/null"
    
    printf "   - Setup remote syslog server & enable fqdn\n"
    Cfg_Cmd "delete system syslog host &> /dev/null"
    Cfg_Cmd "set    system syslog host $NMS_SERVER facility all level err &> /dev/null"
    Cfg_Cmd "set    system syslog host $NMS_SERVER facility daemon level info &> /dev/null"

    # Enable ospf 
    printf "   - Enable OSPF\n"
    Cfg_Cmd "set    protocols ospf parameters router-id 0.0.0.$LOCAL_ID &> /dev/null"
    Cfg_Cmd "set    protocols ospf passive-interface default &> /dev/null"

    # Create IPSec RSA-keys
    # generate ipsec rsa-key if needed
    printf "   - IPSec RSA key\n"
    LOCAL_RSAPUB=""
    if sudo test -f /config/ipsec.d/rsa-keys/localhost.pub; then
        LOCAL_RSAPUB=$(sudo cat /config/ipsec.d/rsa-keys/localhost.pub)
    fi

    if [[ $LOCAL_RSAPUB =~ ^0sAw* ]]; then
        printf "     > Found existing key\n"
    else
        sudo rm -rf /config/ipsec.d/rsa-keys/
        sudo mkdir -p /config/ipsec.d/rsa-keys/
        $ROUTER_RUNCMD generate vpn rsa-key | grep 0sAw | sudo tee /config/ipsec.d/rsa-keys/localhost.pub
        echo ""
        LOCAL_RSAPUB=$(sudo cat /config/ipsec.d/rsa-keys/localhost.pub)
    fi

    Cfg_Cmd "set vpn rsa-keys local-key file /config/ipsec.d/rsa-keys/localhost.key"
    Cfg_Cmd "set vpn rsa-keys  rsa-key-name localhost.pub rsa-key $LOCAL_RSAPUB"

    if [[ $($ROUTER_RUNCMD show unms status | grep status | awk '{print $2}') != "Connected" ]]; then
        printf "   - Enable UNMS\n"
        if [[ $COUNTRY == "CN" ]]; then 
            Cfg_Cmd "set    service unms connection $UNMS_KEY_CN  &> /dev/null"
        else
            Cfg_Cmd "set    service unms connection $UNMS_KEY_US  &> /dev/null"
        fi
    else
        printf "   - UNMS already connected, bypassing\n"
    fi

    printf "   - Enable hardware offload\n"
    # enable hardware offloading engines
    case "$ROUTER_MODEL" in
        "EdgeRouter 10X" | "EdgeRouter X 5-Port")
            Cfg_Cmd "set    system offload hwnat enable  &> /dev/null"
            Cfg_Cmd "set    system offload ipsec enable  &> /dev/null"
            ;;
        *)
            Cfg_Cmd "set    system offload ipsec enable  &> /dev/null"
            Cfg_Cmd "set    system offload ipv4 forwarding enable  &> /dev/null"
            Cfg_Cmd "set    system offload ipv4 gre enable  &> /dev/null"
            Cfg_Cmd "set    system offload ipv4 pppoe enable  &> /dev/null"
            Cfg_Cmd "set    system offload ipv4 vlan enable  &> /dev/null"
            ;;  
    esac

    printf "   - TCP MSS = $TCP_MSS\n"
    Cfg_Cmd "delete firewall options mss-clamp &> /dev/null"
    Cfg_Cmd "set firewall options mss-clamp interface-type all"
    Cfg_Cmd "set firewall options mss-clamp mss $TCP_MSS"
    Cfg_Cmd "set firewall source-validation disable &> /dev/null"

    printf "   - Update GUI port to $GUI_PORT\n"
    Cfg_Cmd "set    service gui https-port $GUI_PORT   &> /dev/null"

    printf "   - Add debian repository for extra packges\n"
    Cfg_Cmd "delete system package repository &> /dev/null"
    Cfg_Cmd "set    system package repository EdgeOS2.0 components \"main contrib non-free\""
    Cfg_Cmd "set    system package repository EdgeOS2.0 distribution stretch"
    Cfg_Cmd "set    system package repository EdgeOS2.0 url http://http.us.debian.org/debian"
    Cfg_Cmd "set    system package repository EdgeOS2.0 username \"\""
    Cfg_Cmd "set    system package repository EdgeOS2.0 password \"\""

    echo -e     "   - Create boot up scripts"
    Generate_Bootup_Scripts "/config/scripts/post-config.d/creekside-bootup.sh"


    return 0
}

# ****************************************************************************
# EdgeOS initialization
# Usage:
#      EdgeOS_Initialization
# ****************************************************************************
function EdgeOS_Initialization() {

    printf    "\n  ---------------------- EdgeOS Initialization ----------------------\n" 
    
    if ! Inquiry_Router_Cfg_Options; then 
        printf  "\n ----------------- Router intialization cancelled --------------------\n\n"
        return 1
    fi

    # make configuration directories
    sudo mkdir -p $CREEKSIDE_ROOT/{conf,scripts,ipsec,deb}

    Cfg_Initiate

    Create_Default_Firewall

    Download_Files

    Install_WireGuard

    EdgeOS_Cfg_WAN_Interface

    EdgeOS_Cfg_LAN_Interface

    Add_External_VPN_Server

    EdgeOS_System_Options

    Create_Security_Zone

    if Cfg_Finalize; then
        printf " o Save configurations\n"
        printf "   - Save [$LOCAL_CFG_FILE]\n"
        Save_Localhost_Cfg $LOCAL_CFG_FILE
        # upload site conf to ftp server
        printf "   - Update site info to ftp server\n"
        Upload_Site_Conf
    fi

    printf  "\n ----------------- Router intialization finished ---------------------\n\n"
    return 0
}

# ****************************************************************************
# Main script
# ****************************************************************************

printf  "\n**********************************************************************\n"
printf    "*                    EdgeOS/VyOS initial script v%-3s                 *\n" "$SCRIPT_VERSION"
printf    "*            (c) Jackson Tong & Creekside Networks LLC 2021          *\n"
printf    "*              Usage: ssh -t ip \"\$(\<./router-init.sh)\"              *\n"
printf    "**********************************************************************\n"

# Root directory of configuration files
CONFIG_ROOT="/config"

# Read version information
# Read hardware ROUTER_MODEL and firmware version
while read -r READ_VALUE; do
    ITEM_NAME=$(echo $READ_VALUE | cut -d ':' -f 1)
    ITEM_VALUE=$(echo $READ_VALUE | cut -d ':' -f 2 | xargs)
    case "$ITEM_NAME" in
        "Version")
            VERSION=$ITEM_VALUE;;
        "HW model")
            MODEL=$ITEM_VALUE;;
    esac    
done < <($ROUTER_RUNCMD show version)

if [[ $VERSION =~ ^VyOS* ]]; then
    ROUTER_TYPE="VyOS"
    MODEL="VyOS"
    VERSION=$(echo $VERSION |  awk '{print $2}')
    if [[ $VERSION != 1.2.8 ]]; then
        printf "\n   *** This scripts only supports VyOS 1.2.8, an ugrade is initiated ***\n\n"
        $ROUTER_RUNCMD "add system image https://www.creekside.network/resources/vyos/isos/vyos-1.2.8-amd64.iso"
        
        printf "\n    *** A reboot is required ***\n\n"
        if Ask_Confirm ">>> Do you want to reboot now?" "N"; then
            sudo reboot
        fi        

        exit 1
    fi
elif [[ $MODEL =~ ^EdgeRouter* ]]; then
    ROUTER_TYPE="EdgeRouter"
    case $MODEL in
        "EdgeRouter X 5-Port"  | "EdgeRouter X SFP" | "EdgeRouter 10X")
            UBNT_HWID="e50";;
        "EdgeRouter Lite" | "EdgeRouter PoE 5-Port")
            UBNT_HWID="e100";;
        "EdgeRouter 8" | "EdgeRouter Pro")
            UBNT_HWID="e200";;
        "EdgeRouter 4" | "EdgeRouter 6P" | "EdgeRouter 12")
            UBNT_HWID="e300";;
        "EdgeRouter Infinity")
            UBNT_HWID="e1000";;
        *)
            printf "\n **** Unsupported EdgeRouter model [$MODEL]\n"
            exit 1
            ;;
    esac
    if ! [[ $VERSION =~ ^v2.* ]]; then
        printf "\n   *** This scripts only supports EdgeOS 2.0, an ugrade is initiated ***\n\n"
        EDGEOS_LINK="https://dl.ui.com/firmwares/edgemax/v2.0.9-hotfix.2/ER-$UBNT_HWID.v2.0.9-hotfix.2.5402463.tar"
        $ROUTER_RUNCMD add system image $EDGEOS_LINK
    
        printf "\n    *** A reboot is required ***\n\n"
        if Ask_Confirm ">>> Do you want to reboot now?" "N"; then
            sudo reboot
        fi        

        exit 1
    fi
else
    printf "\n   *** Unknown device ***\n\n"
    exit 1
fi

printf  "\n o Device information\n"
printf  "%-60s : %s\n" "   - Model"     "$MODEL"
printf  "%-60s : %s\n" "   - Version"   "$VERSION"

Scan_Network_Ports

if ! Load_Localhost_Cfg; then
    printf "\n   *** This Router is not initialized ***\n"
    if ! Ask_Confirm ">>> Do you want to initialize it?" "Y"; then
        exit 0
    fi
else
    printf "\n   *** This Router has already been initialized ***\n"
    if ! Ask_Confirm ">>> Do you want to reinitialize it?" "Y"; then
        exit 0
    fi
fi

if [[ $ROUTER_TYPE == "EdgeRouter" ]]; then
    EdgeOS_Initialization
else
    VyOS_Initialization
fi

printf   "\n **** All done, thank you ****\n\n"

exit 0


