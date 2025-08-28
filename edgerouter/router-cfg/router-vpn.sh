#!/bin/bash
# VyOS/EdgeRouter configuration utility v1
# Now support interactive 
# (c) 2021 Creekside Networks LLC, Jackson Tong
# Usage: ssh -t ip "$(<./router-setup.sh)"

# ****************************************************************************
SCRIPT_VERSION="7.0"
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
UNMS_KEY_CN="wss://unms-cn.creekside.network:8443+UqGw8PU4lHJg0HaR66r7Ipsj1atsB6jDWaA24T9AGg05pHRV+allowSelfSignedCertificate"

DEFAULT_GUEST_VLAN=255
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

WIREGUARD_RELEASE="1.0.20210219"
WIREGUARD_RELEASE_SUB="5"
WIREGUARD_TOOLS="1.0.20210315"
WIREGUARD_DEB_V1=$DEB_DIR/wireguard-v1.deb
WIREGUARD_DEB_V2=$DEB_DIR/wireguard-v2.deb
WIREGUARD_CONF_FILE=$CFG_DIR/wireguard.conf
WIREGUARD_PEER_FILE=$CFG_DIR/wireguard-peers.conf
WIREGUARD_BRINGUP_SCRIPTS=$SCRIPTS_DIR/wireguard-bringup.sh
WIREGUARD_UPDATE_SCRIPTS=$SCRIPTS_DIR/wireguard-update.sh
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
CHINA_DNS3=1.1.1.1

# SDWAN servers
SDWAN_CONF_FILE=$CFG_DIR/sdwan.conf
SDWAN_PEERS_CONF=$CFG_DIR/sdwan-peers.conf
SDWAN_UPDATE_SCRIPTS=$SCRIPTS_DIR/sdwan-update.sh

# install options
GFW_BREAK_ENABLED="N"
GFW_RELAY_ENABLED="N"
GUESTNET_ENABLED="N"
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
                "ROADWARRIOR_GUEST_ENABLED")
                    ROADWARRIOR_GUEST_ENABLED=$VALUE
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
                "GUESTNET_ENABLED")
                    GUESTNET_ENABLED=$VALUE
                    ;;
                "GUESTNET_IF")
                    GUESTNET_IF=$VALUE
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
                    ENA_SECURE_ZONE=$VALUE
                    ;;
                "GUEST_ZONE")
                    ENA_GUEST_ZONE=$VALUE
                    ;;
                "OFFICE_ZONE")
                    ENA_OFFICE_ZONE=$VALUE
                    ;;
                "INTERNET_ZONE")
                    ENA_INTERNET_ZONE=$VALUE
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

    Save_Config_Entry "SECURE_ZONE"             $ENA_SECURE_ZONE 
    Save_Config_Entry "GUEST_ZONE"              $ENA_GUEST_ZONE 
    Save_Config_Entry "OFFICE_ZONE"             $ENA_OFFICE_ZONE 
    Save_Config_Entry "INTERNET_ZONE"           $ENA_INTERNET_ZONE 

    Save_Config_Entry "COUNTRY"                 $COUNTRY                
    Save_Config_Entry "TIMEZONE"                $TIMEZONE               

    Save_Config_Entry "GUESTNET_IF"             $GUESTNET_IF            
    Save_Config_Entry "GUESTNET_ENABLED"        $GUESTNET_ENABLED       

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
    Save_Config_Entry "VPN_GUEST_ENABLE"        $VPN_GUEST_ENABLE
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
#        exit 0
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
   
        if Valid_IP $input; then
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
            "I" | "INTERNET")
                READ_VALUE="INTERNET"
                return 0
                ;;
            "G" | "GUEST")
                READ_VALUE="GUEST"
                return 0
                ;;   
            "O" | "OFFICE")
                READ_VALUE="OFFICE"
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

    sudo curl -fsSL --max-time 10 -u creeksidenetworks:Good2Great $SRC_PATH -o $DEST_FILE

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

# ****************************************************************************
# Generate certs & configuration files for strongswan roadwarrior vpn
# Usage:
#      Generate_Strongswan_Confs
# Apply: EdgeOS/VyOS
# ****************************************************************************
function Generate_Strongswan_Confs() {
    local i
    local index
    local vpn_server_addr=()

    # Inquiry install options
    # collect inputs
    while [[ true ]]; do
        printf "\n o Collect required information\n"
        printf "   - DNS names for the VPN server ('-' to delete)\n"
        i=0
        while [[ true ]]; do
            # use WAN FQDN as default VPN DNS name
            if [[ ${VPN_DNSNAME[$i]} == "" ]] && [[ ${WAN_FQDN[$i]} != "" ]]; then
                VPN_DNSNAME[$i]=${WAN_FQDN[$i]}
            fi

            printf "%-11s %48s : " "     > DNS.$i" "[${VPN_DNSNAME[$i]}]" 
            read INPUT

            case $INPUT in
                "-")
                    if [[ $i == "0" ]]; then
                        printf "\n *** At least one DNS name is required ***\n\n"
                        continue
                    else
                        # end of input, set current dns name to empty indicating the end
                        VPN_DNSNAME[$i]=""
                        break
                    fi
                    ;;
                "")
                    if [[ ${VPN_DNSNAME[$i]} == "" ]]; then
                        # end of input
                        break
                    fi
                    ;;
                *)
                    if Valid_Hostname $INPUT; then
                        if [[ $INPUT == ${INPUT/.} ]]; then
                            # host name only
                            VPN_DNSNAME[$i]=$INPUT.$DEFAULT_DOMAIN
                        else
                            # FQDN
                            VPN_DNSNAME[$i]=$INPUT
                        fi
                    else
                        printf "\n *** A Valid FQDN host name is required ***\n\n"
                        continue
                    fi
                    ;;
            esac

            i=$((i + 1))
        done

        vpn_address[0]=$(curl -s checkip.dyndns.com | sed -e 's/.*Current IP Address: //' -e 's/<.*$//')
        
        printf "\n   - Pick an IP address for the VPN server\n"
        printf "%-20s %-39s\n" "     0. Public IP" "${vpn_address[0]}" 
        index=1
        for(( i=0; i<$NETIF_INDX; i++)) do
            if  [[ ${NETIF_NAME[$i]} =~ ^eth[0-9.]+$ ]] || \
                [[ ${NETIF_NAME[$i]} =~ ^switch[0-9.]+$ ]] || \
                [[ ${NETIF_NAME[$i]} =~ ^pppoe[0-9]+$ ]]; then 
                if [[ ${NETIF_ADDR[$i]} != "-" ]]; then 
                    printf "%-20s %-39s\n" "     $index. ${NETIF_NAME[$i]}" "${NETIF_ADDR[$i]}" 
                    vpn_address[$index]=${NETIF_ADDR[$i]}

                    index=$((index + 1))
                fi
            fi
        done

        printf "%-20s %-39s\n" "     $index. None"
        vpn_address[$index]=""

        Read_Choice ">>> Your choice" "$index" "0" "$index"
        VPN_LOCAL_ADDR=${vpn_address[$READ_VALUE]}

        echo ""
        if Inquiry "   - Use external radius server" "$VPN_RADIUS_ENABLE"; then
            VPN_RADIUS_ENABLE="Y"

            VPN_RADIUS_ADDRESS=${VPN_RADIUS_ADDRESS:-$LOCAL_NS_ADDR}
            Read_IP "     > Radius server address" "$VPN_RADIUS_ADDRESS"
            VPN_RADIUS_ADDRESS=$READ_VALUE

            VPN_RADIUS_SECRET=${VPN_RADIUS_SECRET:-"Good2Great"}
            Read_String "     > Radius server secrets" "$VPN_RADIUS_SECRET" 3 16
            VPN_RADIUS_SECRET=$READ_VALUE


            printf "\n   - Rodwarrior User Groups ('-' to end)\n"
            VPN_USER_POOL="10.$LOCAL_ID.240.0"

             for(( i=0; i<8; i++)) do            
                Read_String  "     $i. Group name" ${ROADWARRIOR_GROUP[$i]:-"-"} 1 16
                ROADWARRIOR_GROUP[$i]=$READ_VALUE

                if [[ $READ_VALUE == "-" ]]; then
                    break;
                fi
                
                ROADWARRIOR_POOL[$i]=$(($i + 240))
                Read_Number "        Address pool - 10.$LOCAL_ID.xxx.0/24" ${ROADWARRIOR_POOL[$i]} 240 247
                ROADWARRIOR_POOL[$i]=$READ_VALUE
            done

            ROADWARRIOR_GROUPNUM=$i

            ROADWARRIOR_DNS_ADDR=$VPN_RADIUS_ADDRESS
            VPN_USER_AUTH="eap-radius"
        else
            VPN_RADIUS_ENABLE="N"
            VPN_USER_AUTH="eap-mschapv2"
        fi

        # dns server for remote users
        ROADWARRIOR_DNS_ADDR=${ROADWARRIOR_DNS_ADDR:-$LOOPBACK_IP}
        
        echo ""
        Read_IP "   - DNS server address" "$ROADWARRIOR_DNS_ADDR"
        ROADWARRIOR_DNS_ADDR=$READ_VALUE

        echo ""
        if  Ask_Confirm "   >>> Do you confirm?"; then
            break
        elif Ask_Confirm "   >>> Return to main menu?"; then
            return 1
        fi
    done  

    printf "\n o Generate Strongswan certificates & configuration files\n"

    printf   "   - Check RSA-keys\n"
    # generate ipsec rsa-key if needed
    if [[ -f $IPSEC_SERVER_KEY ]] && [[ -f $IPSEC_SERVER_PUB ]]; then
        printf   "     > IPSec RSA key found\n"
    else
        printf   "     > Generate IPSec RSA key\n"
        sudo rm -rf $IPSEC_SERVER_KEY
        $ROUTER_RUNCMD generate vpn rsa-key | grep 0sAw | sudo tee $IPSEC_SERVER_PUB
    fi


    # Prepare work directory
    sudo mkdir -p $IPSEC_DIR/{cacerts,certs}

    printf   "   - Download CA certificates\n"
    Ftp_Download_File ftp://$FTP_SERVER/ca/creekside.authority.cer         $IPSEC_CA_CERT 
    Ftp_Download_File ftp://$FTP_SERVER/ca/creekside.authority.key         $IPSEC_CA_KEY  

    printf   "   - Generate CSR\n"

    sudo chmod +r $IPSEC_SERVER_KEY
    openssl req -new -nodes \
        -key $IPSEC_SERVER_KEY \
        -out $IPSEC_CSR \
        -subj "/C=US/O=Creekside Networks LLC/CN=${VPN_DNSNAME[0]}" #&> /dev/null

    echo "authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names

[alt_names]" | tee $IPSEC_CSR_EXT &> /dev/null

    i=0;
    while [[ ${VPN_DNSNAME[$i]} != "" ]]; do
        echo "DNS.$i = ${VPN_DNSNAME[$i]}" | tee -a $IPSEC_CSR_EXT &> /dev/null
        i=$((i + 1))
    done
    
    if [[ $VPN_LOCAL_ADDR != "" ]]; then
        echo "IP.0 = $VPN_LOCAL_ADDR" | tee -a $IPSEC_CSR_EXT &> /dev/null
    fi

    printf   "   - Sign server certificate\n"
    sudo openssl x509 -req -days 3650 -CAcreateserial \
        -in     $IPSEC_CSR \
        -CA     $IPSEC_CA_CERT \
        -CAkey  $IPSEC_CA_KEY  \
        -out    $IPSEC_SERVER_CER \
        -extfile $IPSEC_CSR_EXT  #&> /dev/null 

    # delete temp files
    #sudo mv /tmp/server.key $IPSEC_SERVER_CER
    sudo rm $IPSEC_CA_KEY
    sudo rm $IPSEC_CSR
    sudo rm $IPSEC_CSR_EXT

    printf   "   - Create strongswan configuration files\n"
    # add connections to dipsec.conf
    echo -e "# customized strongswan ipsec configuration
# (c) 2021 Jackson Tong / Creekside Networks LLC

config setup
    uniqueids=never

ca rootca
    cacert=$IPSEC_CA_CERT
    auto=add

conn default
    keyexchange=ikev2
    ike=$IPSEC_IKE_ALG
    esp=$IPSEC_ESP_ALG
    compress=no
    type=tunnel
    fragmentation=yes
    forceencaps=yes
    ikelifetime=4h
    lifetime=2h
    dpddelay=180s
    dpdtimeout=30s
    dpdaction=clear
    rekey=no
    left=%any
    leftcert=$IPSEC_SERVER_CER
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightsendcert=never
    rightdns=$ROADWARRIOR_DNS_ADDR
    rightauth=$VPN_USER_AUTH
    eap_identity=%identity
    auto=ignore
" | sudo tee $IPSEC_CONF  &> /dev/null

    if [[ $VPN_USER_AUTH == "eap-radius" ]]; then 
        for(( i=0; i<8; i++)) do 
            group=${ROADWARRIOR_GROUP[$i]}
            if [[ $group == "-" ]]; then
                break;
            fi

            pool=10.$LOCAL_ID.${ROADWARRIOR_POOL[$i]}.1/24

            echo -e "conn win-$group"                       | sudo tee -a $IPSEC_CONF  &> /dev/null
            echo -e "    also=default"                      | sudo tee -a $IPSEC_CONF  &> /dev/null
            echo -e "    rightgroups=\"$group\""            | sudo tee -a $IPSEC_CONF  &> /dev/null
            echo -e "    rightsourceip=$pool"               | sudo tee -a $IPSEC_CONF  &> /dev/null
            echo -e "    auto=add\n"                        | sudo tee -a $IPSEC_CONF  &> /dev/null

            echo -e "conn mac-$group"                       | sudo tee -a $IPSEC_CONF  &> /dev/null
            echo -e "    also=win-$group"                   | sudo tee -a $IPSEC_CONF  &> /dev/null
            echo -e "    leftid=${VPN_DNSNAME[0]}\n"        | sudo tee -a $IPSEC_CONF  &> /dev/null        
        done
    else
        pool=10.$LOCAL_ID.240.1/24
        echo -e "conn win"                                  | sudo tee -a $IPSEC_CONF  &> /dev/null
        echo -e "    also=default"                          | sudo tee -a $IPSEC_CONF  &> /dev/null
        echo -e "    auto=add"                              | sudo tee -a $IPSEC_CONF  &> /dev/null
        echo -e "    rightsourceip=$pool\n"                 | sudo tee -a $IPSEC_CONF  &> /dev/null

        echo -e "conn mac"                                  | sudo tee -a $IPSEC_CONF  &> /dev/null
        echo -e "    also=win"                              | sudo tee -a $IPSEC_CONF  &> /dev/null
        echo -e "    leftid=${VPN_DNSNAME[0]}\n"            | sudo tee -a $IPSEC_CONF  &> /dev/null  
    fi

    # ipsec.sercrets
    echo -e "# roadwarrior user accounts\n"             | sudo tee $IPSEC_SECRETS  &> /dev/null 
    echo -e ": RSA $IPSEC_SERVER_KEY\n"                 | sudo tee -a $IPSEC_SECRETS  &> /dev/null 
    echo -e "vpnuser : EAP \"vpnpassword\"\n"           | sudo tee -a $IPSEC_SECRETS  &> /dev/null 

    echo -e "charon {
    plugins {
        eap-radius {
            # use class in radius reply for group validation
            class_group = yes
            # local radius server definition
            servers {
                ipa_server {
                    address = $VPN_RADIUS_ADDRESS
                    secret  = $VPN_RADIUS_SECRET
                }
            }
        }
    }
    syslog {
        # prefix for each log message
        identifier = ipsec
        # use default settings to log to the LOG_DAEMON facility
        daemon {
        }
        # detail IKE auditing logs to LOG_AUTHPRIV
        auth {
            default = 1
            ike = 1
            cfg = 1
        }
    }
}"  | sudo tee $IPSEC_STRONGSWAN_CONF  &> /dev/null


    sudo ln -sf $IPSEC_STRONGSWAN_CONF /etc/strongswan.d/creekside_strongswan.conf

    return 0
}

# ****************************************************************************
# Configuration firewall rule sets for Roadwarrior IPSec
# Usage:
#      Cfg_Firewall_IPSec
# Apply: EdgeOS/VyOS
# ****************************************************************************
function Cfg_Firewall_IPSec() {
	Cfg_Comment "\n o Configure firewall rulesets for IPSec\n"

    # Allow IPSec in
    Cfg_Cmd "delete firewall name INTERNET_ROUTER rule 1000 &> /dev/null"
    Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1000 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1000 description 'ipsec-ike/nat'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1000 destination port '500,4500'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1000 protocol 'udp'"

    Cfg_Cmd "delete firewall name INTERNET_ROUTER rule 1001 &> /dev/null"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1001 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1001 description 'ipsec esp'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1001 protocol 'esp'"

}

function Cfg_Firewall_Roadwarrior() {
	Cfg_Comment "\n o Configure firewall rulesets for Roadwarrior\n"

    if [[ $VPN_USER_AUTH == "eap-radius" ]]; then 
        for(( i=0; i<8; i++)) do 
            group=${ROADWARRIOR_GROUP[$i]}
            if [[ $group == "-" ]]; then
                break;
            fi
            pool=10.$LOCAL_ID.${ROADWARRIOR_POOL[$i]}.0/24

            printf "   - User group %s\n" $group
            ipset_name="NETS-VPN-${group^^}" 
            Cfg_Cmd "set firewall group network-group $ipset_name network $pool &> /dev/null"

            ruleid=$((1300 + $i))
            Cfg_Cmd "delete firewall name INTERNET_ROUTER rule $ruleid &> /dev/null"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule $ruleid action 'accept'"
	        Cfg_Cmd "set firewall name INTERNET_ROUTER rule $ruleid description 'Allow VPN $group to access router'"
	        Cfg_Cmd "set firewall name INTERNET_ROUTER rule $ruleid ipsec match-ipsec"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule $ruleid source group network-group $ipset_name"

            Cfg_Cmd "delete firewall name INTERNET_OFFICE rule $ruleid &> /dev/null"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule $ruleid action 'accept'"
	        Cfg_Cmd "set firewall name INTERNET_OFFICE rule $ruleid description 'Allow VPN $group to access office'"
	        Cfg_Cmd "set firewall name INTERNET_OFFICE rule $ruleid ipsec match-ipsec"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule $ruleid source group network-group $ipset_name"
        done
    else
        pool=10.$LOCAL_ID.240.0/24
        ipset_name="NETS-VPN-USER"
        Cfg_Cmd "set firewall group network-group $ipset_name network $pool &> /dev/null"
        
        ruleid=1300
        Cfg_Cmd "delete firewall name INTERNET_ROUTER rule $ruleid &> /dev/null"
        Cfg_Cmd "set firewall name INTERNET_ROUTER rule $ruleid action 'accept'"
	    Cfg_Cmd "set firewall name INTERNET_ROUTER rule $ruleid description 'Allow VPN user to access router'"
	    Cfg_Cmd "set firewall name INTERNET_ROUTER rule $ruleid ipsec match-ipsec"
        Cfg_Cmd "set firewall name INTERNET_ROUTER rule $ruleid source group network-group $ipset_name"

        Cfg_Cmd "delete firewall name INTERNET_OFFICE rule $ruleid &> /dev/null"
        Cfg_Cmd "set firewall name INTERNET_OFFICE rule $ruleid action 'accept'"
	    Cfg_Cmd "set firewall name INTERNET_OFFICE rule $ruleid description 'Allow VPN user to access office'"
	    Cfg_Cmd "set firewall name INTERNET_OFFICE rule $ruleid ipsec match-ipsec"
        Cfg_Cmd "set firewall name INTERNET_OFFICE rule $ruleid source group network-group $ipset_name"
    fi
}


# ****************************************************************************
# Configuration IPSec VPN
# Usage:
#      VyOS_Cfg_IPSec_Roadwarrior
# Apply: VyOS
# ****************************************************************************
function VyOS_Cfg_IPSec_Roadwarrior() {
    local i
    local ipsec_pub
    local ipsec_interface

	Cfg_Comment "\n o Configure IPSec\n"

    # Add VPN configuration
    Cfg_Cmd "set vpn rsa-keys local-key file $IPSEC_SERVER_KEY &> /dev/null"
    ipsec_pub=$(sudo cat $IPSEC_SERVER_PUB)
    Cfg_Cmd "set vpn rsa-keys rsa-key-name localhost.pub rsa-key $ipsec_pub &> /dev/null"

    Cfg_Cmd "set vpn ipsec auto-update 30 &> /dev/null"
    Cfg_Cmd "set vpn ipsec include-ipsec-conf $IPSEC_CONF &> /dev/null"
    Cfg_Cmd "set vpn ipsec include-ipsec-secrets $IPSEC_SECRETS &> /dev/null"

    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_MODE[$i]} == "wan" ]]; then
            ipsec_interface=${NETIF_NAME[$i]}
            printf "   - IPSec interface [%s]\n" "$ipsec_interface"
            Cfg_Cmd "set vpn ipsec ipsec-interfaces interface $ipsec_interface &> /dev/null"
        fi
    done

    if [[ $VPN_LOCAL_INTF != "" ]]; then
        printf "   - IPSec interface [%s]\n" "$VPN_LOCAL_INTF"
        Cfg_Cmd "set vpn ipsec ipsec-interfaces interface $VPN_LOCAL_INTF &> /dev/null"
    fi

	Cfg_Comment "\n o Configure NAT exclude\n"
    # nat exclude
    Cfg_Cmd "delete nat source rule 1240 &> /dev/null"
    Cfg_Cmd "set nat source rule 1240 description \"exclude nat on vpn users\""
    Cfg_Cmd "set nat source rule 1240 destination address $VPN_USER_POOL/21"
    Cfg_Cmd "set nat source rule 1240 exclude"
    Cfg_Cmd "set nat source rule 1240 outbound-interface any"
}

# ****************************************************************************
# Configuration IPSec VPN
# Usage:
#      EdgeOS_Cfg_IPSec_Roadwarrior
# Apply: EdgeOS
# ****************************************************************************
function EdgeOS_Cfg_IPSec_Roadwarrior() {
    local i
    local ipsec_pub
    local ipsec_interface

	Cfg_Comment "\n o Configure IPSec\n"

    # Add VPN configuration
    Cfg_Cmd "set vpn rsa-keys local-key file $IPSEC_SERVER_KEY &> /dev/null"
    ipsec_pub=$(sudo cat $IPSEC_SERVER_PUB)
    Cfg_Cmd "set vpn rsa-keys rsa-key-name localhost.pub rsa-key $ipsec_pub &> /dev/null"

    Cfg_Cmd "set vpn ipsec auto-update 30 &> /dev/null"
    Cfg_Cmd "set vpn ipsec include-ipsec-conf $IPSEC_CONF &> /dev/null"
    Cfg_Cmd "set vpn ipsec include-ipsec-secrets $IPSEC_SECRETS &> /dev/null"

    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_MODE[$i]} == "wan" ]]; then
            ipsec_interface=${NETIF_NAME[$i]}
            printf "   - IPSec interface [%s]\n" "$ipsec_interface"
            Cfg_Cmd "set vpn ipsec ipsec-interfaces interface $ipsec_interface &> /dev/null"
        fi
    done

    if [[ $VPN_LOCAL_INTF != "" ]]; then
        printf "   - IPSec interface [%s]\n" "$VPN_LOCAL_INTF"
        Cfg_Cmd "set vpn ipsec ipsec-interfaces interface $VPN_LOCAL_INTF &> /dev/null"
    fi

}


# ****************************************************************************
# Generate certs & configuration files for strongswan roadwarrior vpn
# Usage:
#      Generate_Strongswan_Confs
# Platform: 
#      EdgeOS/VyOS
# ****************************************************************************
function EdgeOS_StrongSwan_Setup() {

    printf  "\n**********************************************************************\n"
    printf    "*                 Strongswan RoadWarrior VPN Setup                   *\n" 
    printf    "**********************************************************************\n"

    #define encryption algorithm 
    IPSEC_IKE_ALG="aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!"
    IPSEC_ESP_ALG="aes256-sha1,aes128-sha1,3des-sha1!"

    if ! Generate_Strongswan_Confs; then
        printf  "\n ---------------------- Operation Cancelled --------------------------\n\n"
        return 1
    fi
    
    Cfg_Initiate
    
    #Cfg_Firewall_IPSec
    #Cfg_Firewall_Roadwarrior

    EdgeOS_Cfg_IPSec_Roadwarrior

    if Cfg_Finalize; then
        printf " o Save configurations\n"
        printf "   - Save [$LOCAL_CFG_FILE]\n"
        Save_Localhost_Cfg $LOCAL_CFG_FILE
        # upload site conf to ftp server
        printf "   - Update site info to ftp server\n"
        Upload_Site_Conf
    fi

    printf  "\n ------------------- VPN installation finished -----------------------\n\n"
    return 0
}

# ****************************************************************************
# Generate certs & configuration files for strongswan roadwarrior vpn
# Usage:
#      Generate_Strongswan_Confs
# Platform: 
#      EdgeOS/VyOS
# ****************************************************************************
function VyOS_StrongSwan_Setup() {

    printf  "\n**********************************************************************\n"
    printf    "*                 Strongswan RoadWarrior VPN Setup                   *\n" 
    printf    "**********************************************************************\n"

    #define encryption algorithm 
    #IPSEC_IKE_ALG="aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!"
    #IPSEC_ESP_ALG="aes256-sha1,aes128-sha1,3des-sha1!"
    IPSEC_IKE_ALG="aes256-sha1-modp1024"
    IPSEC_ESP_ALG="aes256-sha1"

    if ! Generate_Strongswan_Confs; then
        printf  "\n ---------------------- Operation Cancelled --------------------------\n\n"
        return 1
    fi
    
    if [[ $VPN_RADIUS_ENABLE == "Y" ]]; then
        if [[ $(dpkg-query -W -f='${Status}' freeradius-utils | awk '{print $2}') != 'ok' ]]; then
            printf  "\n o Install \"freeradius-utils\"\n"
            printf  "   - Update \"/etc/apt/sources.list\"\n"
            case $COUNTRY in
                "CN")
                    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ jessie main contrib non-free" | sudo tee      "/etc/apt/sources.list" &> /dev/null 
                    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ jessie-updates main contrib non-free" | sudo tee -a   "/etc/apt/sources.list" &> /dev/null 
                    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ jessie-backports main contrib non-free" | sudo tee -a   "/etc/apt/sources.list" &> /dev/null 
                    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian-security jessie/updates main contrib non-free" | sudo tee -a   "/etc/apt/sources.list" &> /dev/null 
                    ;;
                *) 
                    echo "deb http://ftp.debian.org/debian/ jessie main contrib non-free
deb-src http://ftp.debian.org/debian/ jessie main contrib non-free

deb http://security.debian.org/ jessie/updates main contrib
deb-src http://security.debian.org/ jessie/updates main contrib"  | sudo tee "/etc/apt/sources.list" &> /dev/null                  
                    ;;
            esac
            sudo apt update -y -qq

            printf  "   - Install_Debian_Package \"freeradius-utils\"\n"
            sudo apt install -y -qq freeradius-utils
        fi
    fi

    Cfg_Initiate
    
    #Cfg_Firewall_IPSec
    #Cfg_Firewall_Roadwarrior

    VyOS_Cfg_IPSec_Roadwarrior

    if Cfg_Finalize; then
        printf " o Save configurations\n"
        printf "   - Save [$LOCAL_CFG_FILE]\n"
        Save_Localhost_Cfg $LOCAL_CFG_FILE
        # upload site conf to ftp server
        printf "   - Update site info to ftp server\n"
        Upload_Site_Conf
    fi

    printf  "\n ------------------- VPN installation finished -----------------------\n\n"
    return 0
}


# ****************************************************************************
# Connect another site/router with GRE tunnel by following VPN tunnels
#   *) WireGuard
#   *) IPSec 
# Platform: 
#      EdgeOS/VyOS
# ****************************************************************************
function Add_Intrasite_IPSec() {

    local peer_hostname
    local ospf_enabled="Y"
    local peer_site_file="/tmp/peer.site"

    echo -e "\n ----------------------------------------------------------------------"
    echo -e   " -                   Add site to site VPN tunnel                      -"
    echo -e   " ----------------------------------------------------------------------"

    PEER_ID=""
    DEBUG_ON="Y"

    while [[ true ]]; do
        printf "\n o Select tunnel mode\n"
        printf   "   1) GRE over IPSec\n"
        printf   "   2) GRE over WireGuard\n"
        printf   "   3) Policy based IPSec\n"

        Read_Choice ">>> Your choice" "1" "1" "3"
        case $READ_VALUE in
            "1")
                TUNNEL_MODE="GRE_OVER_IPSEC"
                ;;
            "2")
                TUNNEL_MODE="GRE_OVER_WIREGUARD"
                ;;
            *)
                TUNNEL_MODE="IPSEC"
                echo -e "\n  *** This feature is not implemneted yet ***\n"
                continue
                ;;
        esac

        printf "\n o Local site \n"
        printf  "   - WAN interface for IPSec\n"
        index=0
        for(( i=0; i<$NETIF_INDX; i++)) do
            if [[ ${NETIF_MODE[$i]} == "wan" ]]; then 
                printf  "     %s. %-6s %-45s : %s\n" "$index" ${NETIF_NAME[$i]}  ${NETIF_HOST[$i]:="-"} "[${NETIF_ADDR[$i]}]"
                vpn_if_list[$index]=$i
                index=$((index + 1))
            fi
        done

        if [[ $index -gt 1 ]]; then
            Read_Choice ">>> Select the vpn interface" "0" "0" $((index - 1))
            vpn_if_index=${vpn_if_list[$READ_VALUE]}
            
        else
            vpn_if_index=${vpn_if_list[0]}
        fi

        vpn_if_name=${NETIF_NAME[$vpn_if_index]}
        LOCAL_FQDN=${NETIF_HOST[$vpn_if_index]}

        Read_Hostname "   - Host name" "$LOCAL_FQDN"
        LOCAL_FQDN=$READ_VALUE

        printf "\n o Peer site \n"

        Read_Hostname "   - Host name" "$PEER_FQDN"
        PEER_FQDN=$READ_VALUE

        # download peer site file by hostname
        printf   "     > Download peer site [$PEER_FQDN] information\n"
        sudo rm -f $peer_site_file
            
        curl -fsSL -u creeksidenetworks:Good2Great ftp://$FTP_SERVER/sites/$PEER_FQDN.site -o $peer_site_file
        if ! sudo test -f $peer_site_file; then
            printf   "       **** Peer [%s] site file not found\n\n" $PEER_FQDN
        else
            read -r PEER_ID PEER_FQDN PEER_WGPORT PEER_WGIP PEER_WGPUB PEER_RSA_PUB REMINDER < $peer_site_file
            # delete peer site after reading
            rm -f /tmp/$peer_hostname.site
        fi
 
        Read_Number   "     > Peer ID" "$PEER_ID" "1" "254"
        PEER_ID=$READ_VALUE
        
        case $TUNNEL_MODE in
            "GRE_OVER_IPSEC")
                Read_String   "     > RSA Public Key" "$PEER_RSA_PUB" 300 400
                PEER_RSA_PUB=$READ_VALUE
                LOCAL_OUTSIDE_IP="10.255.$LOCAL_ID.254"
                PEER_OUTSIDE_IP="10.255.$PEER_ID.254"
                ;;
            "GRE_OVER_WIREGUARD")
                Read_String   "     > WG Public Key"  "$PEER_WGPUB" 44 44
                PEER_WGPUB=$READ_VALUE
                LOCAL_OUTSIDE_IP="10.255.255.$LOCAL_ID"
                PEER_OUTSIDE_IP="10.255.255.$PEER_ID"
                PEER_WGPORT=52800
                PEER_WGIP="10.255.255.$PEER_ID"
                ;;
            *)
                echo -e "\n  *** This feature is not implemneted yet ***\n"
                return 1
                ;;
        esac

        printf "\n o Summary of tunnels \n"
        printf "%-60s : %s\n" "   - VPN Mode"               $TUNNEL_MODE
        printf "%-60s : %s\n" "   - Local"                  $LOCAL_FQDN
        printf "%-60s : %s\n" "     > Site ID"              $LOCAL_ID
        printf "%-60s : %s\n" "     > Tunnel outside IP"    $LOCAL_OUTSIDE_IP
        printf "%-60s : %s\n" "   - Peer"                   $PEER_FQDN
        printf "%-60s : %s\n" "     > Site ID"              $PEER_ID
        printf "%-60s : %s\n" "     > Tunnel outside IP"    $PEER_OUTSIDE_IP

        if [[ $PEER_ID -gt $LOCAL_ID ]]; then
            if [[ $PEER_ID -lt "40" ]]; then
                TUN_IP=10.$((PEER_ID+200)).$LOCAL_ID.1/30
                OSPF_NETWORK=10.$((PEER_ID+200)).$LOCAL_ID.0/30
            else
                TUN_IP=10.$PEER_ID.$LOCAL_ID.1/30
                OSPF_NETWORK=10.$PEER_ID.$LOCAL_ID.0/30
            fi
        else
            if [[ $LOCAL_ID -lt "40" ]]; then
                TUN_IP=10.$((LOCAL_ID+200)).$PEER_ID.2/30
                OSPF_NETWORK=10.$((LOCAL_ID+200)).$PEER_ID.0/30
            else
                TUN_IP=10.$LOCAL_ID.$PEER_ID.2/30
                OSPF_NETWORK=10.$LOCAL_ID.$PEER_ID.0/30
            fi
        fi

        TUN_NAME=tun$PEER_ID
        TUN_ZONE="OFFICE"
        printf "\n   - GRE tunnel\n" 
        printf "%-60s : %s\n" "     > Tunnel name"              $TUN_NAME
        printf "%-60s : %s\n" "     > Inner address"            $TUN_IP
        printf "%-60s : %s\n" "     > Local outside address"    $LOCAL_OUTSIDE_IP 
        printf "%-60s : %s\n" "     > Peer  outside address"    $PEER_OUTSIDE_IP
        printf "%-60s : %s\n" "     > Security zone"            $TUN_ZONE
        
        echo ""
        if  Inquiry "   - Add to OSPF configuration?" "$ospf_enabled" "LEFT"; then
            ospf_enabled="Y"
        else
            ospf_enabled="N"
        fi

        echo ""
        if  Ask_Confirm ">>> Do you confirm?"; then
            break
        elif  Ask_Confirm ">>> Return to main menu?" "N"; then
            return 1;
        fi
    done

    # start of configuration portion
    printf "\n o Start configuration\n"
    # start configuration process
    Cfg_Initiate

    if [[ $TUNNEL_MODE == "GRE_OVER_WIREGUARD" ]]; then
        printf "\n   - Update wireguard peer conf\n"
        # Update peer conf file so script can update dynamic peer 
        if sudo test -f $WIREGUARD_PEER_FILE; then
            # found exisitng peer configuration file
            # delete possible existing configurations by ip
            sudo sed -i "\~$PEER_WGIP~d" $WIREGUARD_PEER_FILE &> /dev/null
            # by fqdn
            sudo sed -i "\~$PEER_FQDN~d" $WIREGUARD_PEER_FILE &> /dev/null
            # by pubkey
            sudo sed -i "\~$PEER_WGPUB~d" $WIREGUARD_PEER_FILE &> /dev/null
        fi

        printf "wg0 %-32s %-5s %-15s %s\n" "$PEER_FQDN" "$PEER_WGPORT" "$PEER_WGIP" "$PEER_WGPUB" | sudo tee -a $WIREGUARD_PEER_FILE &> /dev/null

        printf "   - Update WireGuard peers\n"
        $WIREGUARD_UPDATE_SCRIPTS
    elif [[ $TUNNEL_MODE == "GRE_OVER_IPSEC" ]]; then
        printf "\n   - Check IPSec RSA-keys\n"
        Cfg_Cmd "set vpn rsa-keys local-key file /config/ipsec.d/rsa-keys/localhost.key"
        Cfg_Cmd "set vpn rsa-keys rsa-key-name $PEER_FQDN rsa-key $PEER_RSA_PUB"

        ESP_NAME="ESP-AES128-SHA1"
        IKE_NAME="IKE-AES128-SHA1-DH14"


        printf "\n   - Create IPSec tunnel\n"
        Cfg_Cmd "set vpn ipsec esp-group $ESP_NAME compression disable"
        Cfg_Cmd "set vpn ipsec esp-group $ESP_NAME lifetime 3600"
        Cfg_Cmd "set vpn ipsec esp-group $ESP_NAME mode tunnel"
        Cfg_Cmd "set vpn ipsec esp-group $ESP_NAME pfs enable"
        Cfg_Cmd "set vpn ipsec esp-group $ESP_NAME proposal 1 encryption aes128"
        Cfg_Cmd "set vpn ipsec esp-group $ESP_NAME proposal 1 hash sha1"
        Cfg_Cmd "set vpn ipsec ike-group $IKE_NAME ikev2-reauth no"
        Cfg_Cmd "set vpn ipsec ike-group $IKE_NAME key-exchange ikev1"
        Cfg_Cmd "set vpn ipsec ike-group $IKE_NAME lifetime 28800"
        Cfg_Cmd "set vpn ipsec ike-group $IKE_NAME proposal 1 dh-group 14"
        Cfg_Cmd "set vpn ipsec ike-group $IKE_NAME proposal 1 encryption aes128"
        Cfg_Cmd "set vpn ipsec ike-group $IKE_NAME proposal 1 hash sha1"

        Cfg_Cmd "set vpn ipsec ike-group $IKE_NAME dead-peer-detection action restart"
        Cfg_Cmd "set vpn ipsec ike-group $IKE_NAME dead-peer-detection interval 30"
        Cfg_Cmd "set vpn ipsec ike-group $IKE_NAME dead-peer-detection timeout 120"

        Cfg_Cmd "set vpn ipsec ipsec-interfaces interface $vpn_if_name"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  authentication id $LOCAL_FQDN"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  authentication mode rsa"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  authentication remote-id $PEER_FQDN "
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  authentication rsa-key-name $PEER_FQDN"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  connection-type respond"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  description 'gre over ipsec'"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  ike-group $IKE_NAME"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  ikev2-reauth inherit"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  local-address any"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  tunnel 0 esp-group $ESP_NAME"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  tunnel 0 local prefix $LOCAL_OUTSIDE_IP/32"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  tunnel 0 remote prefix $PEER_OUTSIDE_IP/32"

        printf "\n   - Configure Firewall & NAT exclude\n"

        if [[ $ROUTER_TYPE == "VyOS" ]]; then
             Cfg_Cmd "set nat source rule 1 exclude"
             Cfg_Cmd "set nat source rule 1 outbound-interface $vpn_if_name"
             Cfg_Cmd "set nat source rule 1 source address $LOCAL_OUTSIDE_IP/32"
             Cfg_Cmd "set nat source rule 1 description 'Exclude NAT for GRE over IPSec'"
       else
             Cfg_Cmd "set vpn ipsec auto-firewall-nat-exclude enable" 
        fi

    fi

    Cfg_Comment "   - Create GRE tunnel $TUN_NAME\n" 
    Cfg_Cmd "delete interfaces tunnel $TUN_NAME &> /dev/null"
    Cfg_Cmd "set    interfaces tunnel $TUN_NAME address $TUN_IP"
    Cfg_Cmd "set    interfaces tunnel $TUN_NAME description \"$PEER_FQDN\""
    Cfg_Cmd "set    interfaces tunnel $TUN_NAME encapsulation gre"
    Cfg_Cmd "set    interfaces tunnel $TUN_NAME local-ip $LOCAL_OUTSIDE_IP"
    Cfg_Cmd "set    interfaces tunnel $TUN_NAME mtu 1380"
    Cfg_Cmd "set    interfaces tunnel $TUN_NAME multicast disable"
    Cfg_Cmd "set    interfaces tunnel $TUN_NAME remote-ip $PEER_OUTSIDE_IP"

    Cfg_Comment "   - Add interface [$TUN_NAME] to internal zone \n"    
    Cfg_Cmd "set zone-policy zone INTERNAL interface $TUN_NAME &> /dev/null"

    if [[ $ospf_enabled == "Y" ]]; then
        Cfg_Comment "   - Add OSPF configuration\n"
        Cfg_Cmd "set    interfaces tunnel $TUN_NAME ip ospf network point-to-point"
        Cfg_Cmd "set    protocols ospf area 0 network $OSPF_NETWORK"
        Cfg_Cmd "set    protocols ospf passive-interface-exclude $TUN_NAME"
    else
        Cfg_Cmd "delete protocols ospf area 0 network $OSPF_NETWORK &> /dev/null"
        Cfg_Cmd "delete protocols ospf passive-interface-exclude $TUN_NAME &> /dev/null"
    fi

    if Cfg_Finalize; then
        printf " o Save configurations\n"
        printf "   - Save [$LOCAL_CFG_FILE]\n"
        Save_Localhost_Cfg $LOCAL_CFG_FILE
        
        printf  "\n----------------------- Connect site finished ------------------------\n\n"
    fi

    return 0
}

# ****************************************************************************
# Main script
# ****************************************************************************

printf "\n **********************************************************************\n"
printf   " *                    EdgeOS/VyOS IPSec Setup v%-3s                    *\n" "$SCRIPT_VERSION"
printf   " *            (c) Jackson Tong & Creekside Networks LLC 2021          *\n"
printf   " *              Usage: ssh -t ip \"\$(\<./router-ipsec.sh)\"             *\n"
printf   " **********************************************************************\n"


# Root directory of configuration files
CONFIG_ROOT="/config"
ROUTER_TYPE="VyOS"

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
    MODEL="VyOS"
    VERSION=$(echo $VERSION |  awk '{print $2}')
elif [[ $MODEL =~ ^EdgeRouter* ]]; then
    ROUTER_TYPE="EdgeRouter"
fi

printf  "\n o Device information\n"
printf  "%-60s : %s\n" "   - Model"     "$MODEL"
printf  "%-60s : %s\n" "   - Version"   "$VERSION"


Scan_Network_Ports

if ! Load_Localhost_Cfg; then
    printf "\n   *** This router is NOT initialized **** \n\n"
    exit 0
fi

DEFAULT_ACTION="0"
while [[ true ]]; do
    # main menu
    printf   "\n\n o Main menu\n"
    printf   " ----------------------------------------------------------------------\n"
    printf   "   1. Create a site-to-site IPSec tunnel\n"
    printf   "   2. Setup Roadwarrior VPN\n"
    printf   "   0. Exit\n"

    printf   "\n%37s %22s : " ">>> Your choice" "[$DEFAULT_ACTION]"  
    read INPUT
    INPUT=${INPUT:-$DEFAULT_ACTION}

    case "$INPUT" in
        "1")
            Add_Intrasite_IPSec
            ;;
        "2")
            if [[ $MODEL == "VyOS" ]]; then
                VyOS_StrongSwan_Setup
            else
                EdgeOS_StrongSwan_Setup
            fi
            ;;
        "0")
            break
            ;;
        *)
            printf   "\n **** Feature not implemented yet ****\n"
            ;;
    esac
done

printf   "\n **** All done, thank you ****\n\n"

exit 0
