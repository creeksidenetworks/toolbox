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
    done < <($ROUTER_RUNCMD show ip route | grep "0.0.0.0/0" | grep -o 'eth.*\|pppoe.*')



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

    sudo curl -fsSL -u --max-time 10 creeksidenetworks:Good2Great $SRC_PATH -o $DEST_FILE

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

                    NETIF_ZONE[$i]="INTERNET"

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
                    NETIF_ZONE[$i]="INTERNET"
                    break
                fi
            done

            DDNS_WEBCHECK="Y"
        fi

        printf  "\n   - Security zones (Internet/Office/Secure/Guest)\n"
        index=0
        for(( i=0; i<$NETIF_INDX; i++)) do
            if [[ ${NETIF_ADDR[$i]} == "-" ]]; then continue; fi

            if [[ ${NETIF_MODE[$i]} == "lan" ]] || [[ ${NETIF_MODE[$i]} == "wan" ]]; then
                if  [[ ${NETIF_VLAN[$i]} == "255" ]]; then
                    default_zone=${NETIF_ZONE[$i]:-"GUEST"}
                else
                    default_zone=${NETIF_ZONE[$i]:-"OFFICE"}
                fi
                Read_Security_Zone "     > ${NETIF_NAME[$i]} - ${NETIF_ADDR[$i]}" $default_zone
                NETIF_ZONE[$i]=$READ_VALUE

                case ${NETIF_ZONE[$i]} in
                    "INTERNET")
                        ENA_INTERNET_ZONE="Y"
                        ;;
                    "SECURE")
                        ENA_SECURE_ZONE="Y"
                        ;;
                    "GUEST")
                        ENA_GUEST_ZONE="Y"
                        ;;
                    "OFFICE")
                        ENA_OFFICE_ZONE="Y"
                        ;;
                    *)
                        printf "\n *** Invalid security zone ' ${NETIF_ZONE[$i]}' ***\n\n"
                        exit 1
                        ;;
                esac
            fi
        done

        # Compatibility with old scripts
        INSTALL_WG0="Y"
        ENA_OFFICE_ZONE="Y"  # wg0 is in office zone by default

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
# Add secure zone to firewall
# Usage:
#      Add_Secure_Zone
# ****************************************************************************
function Add_Secure_Zone() {
	Cfg_Comment "   - Secure zone"
 
    # exempted servers are allowed to access internet & office for software installation purpose
 	Cfg_Cmd "set firewall group address-group ADDR-SECSRV-EXEMPTED description 'secure servers allowed internet access' &> /dev/null"
 	Cfg_Cmd "set firewall group port-group PORTS-REMOTE-DESKTOP description 'Remote desktop access port, vnc & RDP'"
    Cfg_Cmd "set firewall group port-group PORTS-REMOTE-DESKTOP port 3389"
    Cfg_Cmd "set firewall group port-group PORTS-REMOTE-DESKTOP port 5900-5999"

    if [[ $IPA_ENABLED == "Y" ]]; then
        Cfg_Cmd "set firewall group address-group ADDR-IPA-SERVERS address $IPA_SERVER_IP"

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

        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-UDP port 138"
        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-UDP port 139"
        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-UDP port 389"
        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-UDP port 445"

        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-TCP port 135"
        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-TCP port 138"
        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-TCP port 139"
        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-TCP port 445"
        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-TCP port 1024-1300"
        Cfg_Cmd "set firewall group port-group PORTS-IPA-ADTRUST-TCP port 3268"
    fi

    # internet to secure zone rule set
	Cfg_Cmd "delete firewall name INTERNET_SECURE &> /dev/null"
	Cfg_Cmd "set firewall name INTERNET_SECURE default-action 'drop'"
	Cfg_Cmd "set firewall name INTERNET_SECURE description 'internet to secure'"
	Cfg_Cmd "set firewall name INTERNET_SECURE rule 1 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_SECURE rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name INTERNET_SECURE rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name INTERNET_SECURE rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name INTERNET_SECURE rule 2 action 'drop'"
	Cfg_Cmd "set firewall name INTERNET_SECURE rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name INTERNET_SECURE rule 2 state invalid 'enable'"

    # office to secure zone rule set
	Cfg_Cmd "delete firewall name OFFICE_SECURE &> /dev/null"
	Cfg_Cmd "set firewall name OFFICE_SECURE default-action 'drop'"
	Cfg_Cmd "set firewall name OFFICE_SECURE description 'office to secure'"

	Cfg_Cmd "set firewall name OFFICE_SECURE rule 1 action 'accept'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2 action 'drop'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2 state invalid 'enable'"

	Cfg_Cmd "set firewall name OFFICE_SECURE rule 3000 action 'accept'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 3000 description 'allow remote desktop access only'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 3000 destination group port-group PORTS-REMOTE-DESKTOP"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 3000 protocol tcp"

	Cfg_Cmd "set firewall group network-group NETS-TRUSTED-USERS description 'Secure users' &> /dev/null"

	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2000 action 'accept'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2000 description 'allow intra-secure zone traffic'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2000 destination group network-group 'NETS-SECURE-ZONE'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2000 source group network-group 'NETS-SECURE-ZONE'"

	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2010 action 'accept'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2010 description 'allow secure users full access'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2010 source group network-group NETS-TRUSTED-USERS"

	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2020 action 'accept'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2020 description 'allow full access to exempted servers'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2020 destination group address-group ADDR-SECSRV-EXEMPTED"

    Cfg_Cmd "set firewall name OFFICE_SECURE rule 2030 action 'accept'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2030 description 'allow IPA servers to access secure zone'"
	Cfg_Cmd "set firewall name OFFICE_SECURE rule 2030 source group address-group ADDR-IPA-SERVERS"

    # secure zone  
	Cfg_Cmd "delete zone-policy zone SECURE &> /dev/null"
	Cfg_Cmd "set zone-policy zone SECURE default-action 'drop'"
	Cfg_Cmd "set zone-policy zone SECURE from ROUTER firewall name 'DEFAULT_ACCEPT'"
	Cfg_Cmd "set zone-policy zone SECURE from INTERNET firewall name 'INTERNET_SECURE'"
	Cfg_Cmd "set zone-policy zone SECURE from OFFICE firewall name 'OFFICE_SECURE'"

	Cfg_Cmd "set firewall group network-group NETS-SECURE-ZONE description 'Secure zone networks'"

    # secure to office zone rule set
	Cfg_Cmd "delete firewall name SECURE_OFFICE &> /dev/null"
	Cfg_Cmd "set firewall name SECURE_OFFICE default-action 'drop'"
	Cfg_Cmd "set firewall name SECURE_OFFICE description 'secure to office'"

	Cfg_Cmd "set firewall name SECURE_OFFICE rule 1 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2 action 'drop'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2 state invalid 'enable'"
	    
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 110 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 110 description 'allow ping office'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 110 icmp type-name 'echo-request'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 110 destination group network-group NETS-PRIVATE"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 110 protocol 'icmp'"


	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2000 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2000 description 'allow intra-secure zone traffic'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2000 destination group network-group 'NETS-SECURE-ZONE'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2000 source group network-group 'NETS-SECURE-ZONE'"

	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2050 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2050 description 'allow exempted server access office'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2050 source group address-group ADDR-SECSRV-EXEMPTED"

    Cfg_Cmd "set firewall name SECURE_OFFICE rule 2030 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2030 description 'allow IPA servers to access secure zone'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2030 destination group address-group ADDR-IPA-SERVERS"
    Cfg_Cmd "set firewall name SECURE_OFFICE rule 2030 destination group port-group PORTS-IPA-SERVERS-TCP"
    Cfg_Cmd "set firewall name SECURE_OFFICE rule 2030 protocol tcp"

    Cfg_Cmd "set firewall name SECURE_OFFICE rule 2031 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2031 description 'allow IPA servers to access secure zone'"
	Cfg_Cmd "set firewall name SECURE_OFFICE rule 2031 destination group address-group ADDR-IPA-SERVERS"
    Cfg_Cmd "set firewall name SECURE_OFFICE rule 2031 destination group port-group PORTS-IPA-SERVERS-UDP"
    Cfg_Cmd "set firewall name SECURE_OFFICE rule 2031 protocol udp"

    # office zone 
	Cfg_Cmd "set zone-policy zone OFFICE from SECURE firewall name 'SECURE_OFFICE'"

    # secure to internet zone rule set 
        
	Cfg_Cmd "delete firewall name SECURE_INTERNET &> /dev/null"
	Cfg_Cmd "set firewall name SECURE_INTERNET default-action 'drop'"
	Cfg_Cmd "set firewall name SECURE_INTERNET description 'secure to internet'"

	Cfg_Cmd "set firewall name SECURE_INTERNET rule 1 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 2 action 'drop'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 2 state invalid 'enable'"

	Cfg_Cmd "set firewall name SECURE_INTERNET rule 123 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 123 description 'allow ntp'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 123 destination port 123"
    Cfg_Cmd "set firewall name SECURE_INTERNET rule 123 protocol udp"

	Cfg_Cmd "set firewall name SECURE_INTERNET rule 2000 action 'accept'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 2000 description 'allow exempted server access internet'"
	Cfg_Cmd "set firewall name SECURE_INTERNET rule 2000 source group address-group ADDR-SECSRV-EXEMPTED"

	Cfg_Cmd "set zone-policy zone INTERNET from SECURE firewall name 'SECURE_INTERNET'"

    # local zone
	Cfg_Cmd "set zone-policy zone ROUTER  from SECURE firewall name 'DEFAULT_ACCEPT'"
}

# ****************************************************************************
# Add guest zone to firewall
# Usage:
#      Add_Guest_Zone
# ****************************************************************************
function Add_Guest_Zone() {
	Cfg_Comment "   - Guest zone"
 
    # internet to guest zone rule set
	Cfg_Cmd "delete firewall name INTERNET_GUEST &> /dev/null"
	Cfg_Cmd "set firewall name INTERNET_GUEST default-action 'drop'"
	Cfg_Cmd "set firewall name INTERNET_GUEST description 'internet to secure'"
	Cfg_Cmd "set firewall name INTERNET_GUEST rule 1 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_GUEST rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name INTERNET_GUEST rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name INTERNET_GUEST rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name INTERNET_GUEST rule 2 action 'drop'"
	Cfg_Cmd "set firewall name INTERNET_GUEST rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name INTERNET_GUEST rule 2 state invalid 'enable'"

    # guest to router zone rule set
    Cfg_Cmd "delete firewall name GUEST_ROUTER &> /dev/null"
	Cfg_Cmd "set firewall name GUEST_ROUTER default-action 'drop'"
	Cfg_Cmd "set firewall name GUEST_ROUTER description 'guest to router'"
    
    Cfg_Cmd "set firewall name GUEST_ROUTER rule 1 action 'accept'"
	Cfg_Cmd "set firewall name GUEST_ROUTER rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name GUEST_ROUTER rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name GUEST_ROUTER rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name GUEST_ROUTER rule 2 action 'drop'"
	Cfg_Cmd "set firewall name GUEST_ROUTER rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name GUEST_ROUTER rule 2 state invalid 'enable'"

    Cfg_Cmd "set firewall name GUEST_ROUTER rule 1100 action 'accept'"
	Cfg_Cmd "set firewall name GUEST_ROUTER rule 1100 description 'allow guest access DHCP'" 
    Cfg_Cmd "set firewall name GUEST_ROUTER rule 1100 destination port 67"
    Cfg_Cmd "set firewall name GUEST_ROUTER rule 1100 protocol udp"

    Cfg_Cmd "set firewall name GUEST_ROUTER rule 1110 action 'accept'"
	Cfg_Cmd "set firewall name GUEST_ROUTER rule 1110 description 'allow guest access DNS'"
    Cfg_Cmd "set firewall name GUEST_ROUTER rule 1110 destination port 53"
    Cfg_Cmd "set firewall name GUEST_ROUTER rule 1110 protocol tcp_udp"

    # guest to router zone rule set
    Cfg_Cmd "delete firewall name GUEST_OFFICE &> /dev/null"
	Cfg_Cmd "set firewall name GUEST_OFFICE default-action 'drop'"
	Cfg_Cmd "set firewall name GUEST_OFFICE description 'guest to router'"
    
    Cfg_Cmd "set firewall name GUEST_OFFICE rule 1 action 'accept'"
	Cfg_Cmd "set firewall name GUEST_OFFICE rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name GUEST_OFFICE rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name GUEST_OFFICE rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name GUEST_OFFICE rule 2 action 'drop'"
	Cfg_Cmd "set firewall name GUEST_OFFICE rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name GUEST_OFFICE rule 2 state invalid 'enable'"

    # guest zone  
	Cfg_Cmd "delete zone-policy zone GUEST &> /dev/null"
	Cfg_Cmd "set zone-policy zone GUEST default-action 'drop'"
	Cfg_Cmd "set zone-policy zone GUEST from ROUTER firewall name 'DEFAULT_ACCEPT'"
	Cfg_Cmd "set zone-policy zone GUEST from INTERNET firewall name 'INTERNET_GUEST'"
	Cfg_Cmd "set zone-policy zone GUEST from OFFICE firewall name 'DEFAULT_ACCEPT'"

	Cfg_Cmd "set zone-policy zone INTERNET from GUEST firewall name 'DEFAULT_ACCEPT'"
	Cfg_Cmd "set zone-policy zone OFFICE from GUEST firewall name 'GUEST_OFFICE'"
    Cfg_Cmd "set zone-policy zone ROUTER from GUEST firewall name 'GUEST_ROUTER'"
}

# ****************************************************************************
# Create default zone base firewall, only internet and local zones are created
# Usage:
#      Create_Default_Firewall
# ****************************************************************************
function VPN_Update_Firewall() {
    Cfg_Cmd "set firewall group network-group NETS-VPN-GUEST description 'VPN Guest subnets' &> /dev/null"

    # Allow VPN guest to access FreeIPA
    Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1100 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1100 description 'allow guest access FreeIPA'" 
    Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1100 source group network-group NETS-VPN-GUEST"
    Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1100 destination port 443"
    Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1100 destination group address-group ADDR-IPA-SERVERS"
    Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1100 protocol tcp"

}

# ****************************************************************************
# Create default zone base firewall, only internet and local zones are created
# Usage:
#      Create_Default_Firewall
# ****************************************************************************
function Create_Default_Firewall() {

    Cfg_Comment "\n o Setup default firewall"
    Cfg_Comment "   - Define firewall groups"
	
	Cfg_Cmd "set firewall group network-group NETS-PRIVATE description 'private networks' &> /dev/null"
	Cfg_Cmd "set firewall group network-group NETS-PRIVATE network '10.0.0.0/8' &> /dev/null"
	Cfg_Cmd "set firewall group network-group NETS-PRIVATE network '172.16.0.0/12' &> /dev/null"
	Cfg_Cmd "set firewall group network-group NETS-PRIVATE network '192.168.0.0/16' &> /dev/null"

    Cfg_Cmd "set firewall group port-group PORTS-MGT description 'management ports' &> /dev/null"
	Cfg_Cmd "set firewall group port-group PORTS-MGT port '22' &> /dev/null"

    Cfg_Cmd "set firewall group port-group PORTS-WIREGUARD description 'WireGuard ports' &> /dev/null"
	Cfg_Cmd "set firewall group port-group PORTS-WIREGUARD port '52800' &> /dev/null"
    Cfg_Cmd "set firewall group port-group PORTS-WIREGUARD port '52801' &> /dev/null"

    Cfg_Cmd "set firewall group address-group ADDR-IPA-SERVERS description 'IPA servers' &> /dev/null"

    Cfg_Cmd "delete zone-policy &> /dev/null"

    Cfg_Comment "   - Internet zone"
    Cfg_Cmd "delete firewall name INTERNET_ROUTER &> /dev/null"
	Cfg_Cmd "set firewall name INTERNET_ROUTER default-action 'drop'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER description 'internet to router'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 2 action 'drop'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 2 state invalid 'enable'"

	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 100 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 100 description 'allow remote management'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 100 destination group port-group 'PORTS-MGT'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 100 protocol 'tcp'"

	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 110 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 110 description 'allow ping from INTERNET'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 110 icmp type-name 'echo-request'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 110 protocol 'icmp'"

	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 120 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 120 description 'allow WireGuard'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 120 destination group port-group 'PORTS-WIREGUARD'"
	Cfg_Cmd "set firewall name INTERNET_ROUTER rule 120 protocol 'udp'"

#    Cfg_Cmd "delete zone-policy zone INTERNET &> /dev/null"
	Cfg_Cmd "set zone-policy zone INTERNET default-action 'drop'"
	Cfg_Cmd "set zone-policy zone INTERNET description 'internet zone'"
	Cfg_Cmd "set zone-policy zone INTERNET from ROUTER firewall name 'DEFAULT_ACCEPT'"
    Cfg_Cmd "set zone-policy zone INTERNET from OFFICE firewall name 'DEFAULT_ACCEPT'"

    Cfg_Comment "   - Default accept & drop rulesets"
	Cfg_Cmd "set firewall name DEFAULT_ACCEPT default-action 'accept' &> /dev/null"
	Cfg_Cmd "set firewall name DEFAULT_DROP default-action 'drop' &> /dev/null"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 1 action 'accept'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 2 action 'drop'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name DEFAULT_DROP rule 2 state invalid 'enable'"

#    Cfg_Cmd "delete zone-policy zone ROUTER  &> /dev/null"
    Cfg_Comment "   - Local zone"
	Cfg_Cmd "set zone-policy zone ROUTER  default-action 'drop'"
	Cfg_Cmd "set zone-policy zone ROUTER  from INTERNET firewall name 'INTERNET_ROUTER'"
    Cfg_Cmd "set zone-policy zone ROUTER  from OFFICE firewall name 'DEFAULT_ACCEPT'"
	Cfg_Cmd "set zone-policy zone ROUTER  local-zone"

    Cfg_Comment "   - Office zone"
    Cfg_Cmd "delete firewall name INTERNET_OFFICE &> /dev/null"
	Cfg_Cmd "set firewall name INTERNET_OFFICE default-action 'drop'"
	Cfg_Cmd "set firewall name INTERNET_OFFICE description 'internet to office'"
	Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1 action 'accept'"
	Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1 description 'allow established/related'"
	Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1 state established 'enable'"
	Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1 state related 'enable'"
	Cfg_Cmd "set firewall name INTERNET_OFFICE rule 2 action 'drop'"
	Cfg_Cmd "set firewall name INTERNET_OFFICE rule 2 description 'drop invalid state'"
	Cfg_Cmd "set firewall name INTERNET_OFFICE rule 2 state invalid 'enable'"

#    Cfg_Cmd "delete zone-policy zone OFFICE &> /dev/null"
	Cfg_Cmd "set zone-policy zone OFFICE default-action 'drop'"
	Cfg_Cmd "set zone-policy zone OFFICE from ROUTER firewall name 'DEFAULT_ACCEPT'"
	Cfg_Cmd "set zone-policy zone OFFICE from INTERNET firewall name 'INTERNET_OFFICE'"

    if [[ $ENA_SECURE_ZONE == "Y" ]]; then
        Add_Secure_Zone
    fi

    if [[ $ENA_GUEST_ZONE == "Y" ]]; then
        Add_Guest_Zone
    fi
}
# ****************************************************************************
# Install WireGuard interfaces on VyOS/EdgeRouter
# Usage:
#      Install_WireGuard
# ****************************************************************************
Install_WireGuard() {

    Cfg_Comment "\n o Install WireGuard interfaces"

    printf   "   - Download WireGuard scripts\n"
    Ftp_Download_File ftp://$FTP_SERVER/scripts/wireguard-bringup.sh        $WIREGUARD_BRINGUP_SCRIPTS 
    Ftp_Download_File ftp://$FTP_SERVER/scripts/wireguard-update.sh         $WIREGUARD_UPDATE_SCRIPTS 
    sudo chmod +x $WIREGUARD_BRINGUP_SCRIPTS
    sudo chmod +x $WIREGUARD_UPDATE_SCRIPTS
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

    printf "%-60s : %s\n" "   - Firewall zone" "OFFICE"
    Cfg_Cmd "set zone-policy zone OFFICE interface wg0 &> /dev/null"
    Cfg_Cmd "set zone-policy zone OFFICE interface wg1 &> /dev/null"

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
    Cfg_Cmd "set    service dns dynamic interface $interface service cloudflare zone $domain"
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

            Cfg_Cmd "set zone-policy zone INTERNET interface ${NETIF_NAME[$i]}"

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

    for ((i=0; i<$NETIF_INDX; i++)) do
        # assign proper security zone
        if [[ ${NETIF_MODE[$i]} == "lan" ]] && [[ ${NETIF_ADDR[$i]} != '-' ]]; then
            printf "%-42s %-17s : %s\n" "   - ${NETIF_NAME[$i]}" "${NETIF_ADDR[$i]}" "${NETIF_ZONE[$i]}"
            case ${NETIF_ZONE[$i]} in
                "SECURE" | "OFFICE" | "INTERNET")
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


    # loopback interface
    LOOPBACK_IP=10.255.$LOCAL_ID.254
    printf "%-42s %-17s : %s\n" "   - loopback" "$LOOPBACK_IP" "router"
    Cfg_Cmd "set interfaces loopback lo address $LOOPBACK_IP/32 &> /dev/null"
    Cfg_Cmd "set service dns forwarding listen-address $LOOPBACK_IP &> /dev/null"

    return 0
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
        CREEKSIDE_BOOTUP_SCRIPTS="/config/scripts/vyos-postconfig-bootup.script"

    echo "#!/bin/bash
# VyOS boot up scripts
# By Creekside Networks LLC, 2021

# Bringup WireGuard interfaces
$WIREGUARD_BRINGUP_SCRIPTS
$WIREGUARD_UPDATE_SCRIPTS

# Enable fqdn to be used in remote syslog
echo \"\\\$PreserveFQDN on\" | sudo tee /etc/rsyslog.d/remote.conf &> /dev/null
sudo service rsyslog restart
" | sudo tee $CREEKSIDE_BOOTUP_SCRIPTS &> /dev/null
    sudo chmod +x $CREEKSIDE_BOOTUP_SCRIPTS

#    echo "   - Add wireguard peer update script to task scheduler"
#    Cfg_Cmd "set system task-scheduler task update.wireguard interval 2m  &> /dev/null"
#    Cfg_Cmd "set system task-scheduler task update.wireguard executable path $WIREGUARD_UPDATE_SCRIPTS  &> /dev/null"

    return 0
}


# ****************************************************************************
# VyOS initialization
# Usage:
#      VyOS_Initialization
# ****************************************************************************
function VyOS_Initialization() {

    printf  "\n**********************************************************************\n"
    printf    "*                         VyOS Initialization                        *\n" 
    printf    "**********************************************************************\n"
    
    if ! Inquiry_Router_Cfg_Options; then 
        printf  "\n ----------------- Router intialization cancelled --------------------\n\n"
        return 1
    fi

    # make configuration directories
    sudo mkdir -p $CREEKSIDE_ROOT/{conf,scripts,ipsec}

    Cfg_Initiate

    Create_Default_Firewall

    if [[ $INSTALL_WG0 == "Y" ]]; then
        Install_WireGuard
    fi

    VyOS_Cfg_WAN_Interface

    VyOS_Cfg_LAN_Interface

    VyOS_System_Options

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
# EdgeOS Install WireGuard
# Usage:
#      EdgeOS_Install_WireGuard
# ****************************************************************************
function EdgeOS_Install_WireGuard() {
    printf "\n o Install WireGuard packages\n"
    if [[ $(dpkg-query -W -f='${Status}' wireguard | awk '{print $2}') != 'ok' ]]; then
        printf   "   - WireGuard Not installed\n"
        printf   "     > Download %s\n" "${UBNT_HWID}-v2-v${WIREGUARD_RELEASE}-v${WIREGUARD_TOOLS}.deb"
        sudo curl -fsSL https://github.com/WireGuard/wireguard-vyatta-ubnt/releases/download/${WIREGUARD_RELEASE}-${WIREGUARD_RELEASE_SUB}/${UBNT_HWID}-v2-v${WIREGUARD_RELEASE}-v${WIREGUARD_TOOLS}.deb \
                -o $WIREGUARD_DEB_V2
        if ! sudo test -f $WIREGUARD_DEB_V2; then
            printf "\n *** Download failed, exit now\n\n"
            echo "        sudo curl -fsSL https://github.com/WireGuard/wireguard-vyatta-ubnt/releases/download/${WIREGUARD_RELEASE}-${WIREGUARD_RELEASE_SUB}/${UBNT_HWID}-v2-v${WIREGUARD_RELEASE}-v${WIREGUARD_TOOLS}.deb -o $WIREGUARD_DEB_V2"
            exit 1
        fi
        printf   "     > Install WireGuard release ${WIREGUARD_RELEASE}\n"
        sudo dpkg -i $WIREGUARD_DEB_V2 &> /dev/null
    fi

    Install_WireGuard

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

            Cfg_Cmd "set zone-policy zone INTERNET interface ${NETIF_NAME[$i]}"

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
        printf "   - Add Creekside unifi-controller, $unifi_ip\n"
        Cfg_Cmd "set    service dns forwarding options host-record=unifi,$unifi_ip &> /dev/null"
    fi

    printf "\n o Configure local interfaces\n"

    for ((i=0; i<$NETIF_INDX; i++)) do
        if [[ ${NETIF_MODE[$i]} == "lan" ]] || [[ ${NETIF_MODE[$i]} == "local" ]]; then 
            # assign proper security zone
            NETIF_ZONE[$i]=${NETIF_ZONE[$i]:-"OFFICE"}
            printf "%-42s %-17s : %s\n" "   - ${NETIF_NAME[$i]}" "${NETIF_ADDR[$i]}" "${NETIF_ZONE[$i]}"

            case ${NETIF_ZONE[$i]} in
                "SECURE" | "OFFICE" | "GUEST" | "INTERNET")
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
    CREEKSIDE_BOOTUP_SCRIPTS="/config/scripts/post-config.d/creekside-bootup.sh"

    echo "#!/bin/bash"                                  | sudo tee    $CREEKSIDE_BOOTUP_SCRIPTS &> /dev/null
    echo "# EdgeRouter boot up scripts, Creekside 2021" | sudo tee -a $CREEKSIDE_BOOTUP_SCRIPTS &> /dev/null
    echo "echo \"\\\$PreserveFQDN on\" | sudo tee /etc/rsyslog.d/remote.conf &> /dev/null"  | sudo tee -a $CREEKSIDE_BOOTUP_SCRIPTS &> /dev/null
    echo "sudo service rsyslog restart"                 | sudo tee -a $CREEKSIDE_BOOTUP_SCRIPTS &> /dev/null
    echo "$WIREGUARD_BRINGUP_SCRIPTS "                  | sudo tee -a $CREEKSIDE_BOOTUP_SCRIPTS &> /dev/null
    echo "$WIREGUARD_UPDATE_SCRIPTS"                    | sudo tee -a $CREEKSIDE_BOOTUP_SCRIPTS &> /dev/null
    sudo chmod +x $CREEKSIDE_BOOTUP_SCRIPTS

    return 0
}

# ****************************************************************************
# EdgeOS initialization
# Usage:
#      EdgeOS_Initialization
# ****************************************************************************
function EdgeOS_Initialization() {

    printf  "\n**********************************************************************\n"
    printf    "*                        EdgeOS Initialization                       *\n" 
    printf    "**********************************************************************\n"
    
    if ! Inquiry_Router_Cfg_Options; then 
        printf  "\n ----------------- Router intialization cancelled --------------------\n\n"
        return 1
    fi

    # make configuration directories
    sudo mkdir -p $CREEKSIDE_ROOT/{conf,scripts,ipsec,deb}

    Cfg_Initiate

    Create_Default_Firewall

    if [[ $INSTALL_WG0 == "Y" ]]; then
        EdgeOS_Install_WireGuard
    fi

    EdgeOS_Cfg_WAN_Interface

    EdgeOS_Cfg_LAN_Interface

    EdgeOS_System_Options

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
    
    Cfg_Firewall_IPSec
    Cfg_Firewall_Roadwarrior

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
                    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ buster main contrib non-free" | sudo tee      "/etc/apt/sources.list" &> /dev/null 
                    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ buster-updates main contrib non-free" | sudo tee -a   "/etc/apt/sources.list" &> /dev/null 
                    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ buster-backports main contrib non-free" | sudo tee -a   "/etc/apt/sources.list" &> /dev/null 
                    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian-security buster/updates main contrib non-free" | sudo tee -a   "/etc/apt/sources.list" &> /dev/null 
                    ;;
                *) 
                    echo "deb http://deb.debian.org/debian buster main"                         | sudo tee "/etc/apt/sources.list" &> /dev/null
                    echo "deb-src http://deb.debian.org/debian buster main"                     | sudo tee -a "/etc/apt/sources.list" &> /dev/null

                    echo "deb http://deb.debian.org/debian-security/ buster/updates main"       | sudo tee -a "/etc/apt/sources.list" &> /dev/null
                    echo "deb-src http://deb.debian.org/debian-security/ buster/updates main"   | sudo tee -a "/etc/apt/sources.list" &> /dev/null

                    echo "deb http://deb.debian.org/debian buster-updates main"                 | sudo tee -a "/etc/apt/sources.list" &> /dev/null
                    echo "deb-src http://deb.debian.org/debian buster-updates main"             | sudo tee -a "/etc/apt/sources.list" &> /dev/null                  
                    ;;
            esac
            sudo apt update -y -qq

            printf  "   - Install_Debian_Package \"freeradius-utils\"\n"
            sudo apt install -y -qq freeradius-utils
        fi
    fi

    Cfg_Initiate
    
    Cfg_Firewall_IPSec
    Cfg_Firewall_Roadwarrior

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
function Connect_Site() {

    local peer_hostname
    local ospf_enabled="Y"
    local peer_site_file="/tmp/peer.site"

    printf  "\n**********************************************************************\n"
    printf    "*                     Connect with another site                      *\n" 
    printf    "**********************************************************************\n"

    DEFAULT_ACTION="0"
    TUNNEL_MODE="1"
    PEER_ID=""

    DEBUG_ON="Y"

    while [[ true ]]; do
        printf "\n o Select tunnel mode\n"
        printf   "   1) IPSec IKEv1\n"
        printf   "   2) WireGuard\n"

        Read_Choice ">>> Your choice" "1" "1" "2"
        case $READ_VALUE in
            "1")
                TUNNEL_MODE="IPSec"
                ;;
            *)
                TUNNEL_MODE="WireGuard"
                ;;
        esac

        printf "\n o Local site \n"
        printf  "   - WAN interface for VPN tunnel\n"
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
        
        if [[ $TUNNEL_MODE == "WireGuard" ]]; then
            LOCAL_OUTSIDE_IP=10.255.255.$LOCAL_ID 

            PEER_WGPORT=${PEER_WGPORT:-"52800"}
            Read_Number   "     > Listen Port" "$PEER_WGPORT" 10000 65535
            PEER_WGPORT=$READ_VALUE

            PEER_OUTSIDE_IP=${PEER_WGIP:-"10.255.255.$PEER_ID"}
            Read_IP       "     > Address" "$PEER_OUTSIDE_IP"
            PEER_OUTSIDE_IP=$READ_VALUE

            Read_String   "     > Public key" "$PEER_WGPUB" 44 44
            PEER_WGPUB=$READ_VALUE
        else
            LOCAL_OUTSIDE_IP="10.255.$LOCAL_ID.254"

            PEER_OUTSIDE_IP=${PEER_OUTSIDE_IP:-"10.255.$PEER_ID.254"}

            Read_String   "     > RSA Public Key" "$PEER_RSA_PUB" 300 400
            PEER_RSA_PUB=$READ_VALUE
        fi

        printf "\n o Summary of tunnels \n"
        printf "%-60s : %s\n" "   - VPN Mode"               $TUNNEL_MODE
        printf "%-60s : %s\n" "   - Local"                  $LOCAL_FQDN
        printf "%-60s : %s\n" "     > Site ID"              $LOCAL_ID
        printf "%-60s : %s\n" "     > Loopback interface"   $LOCAL_OUTSIDE_IP
        printf "%-60s : %s\n" "   - Peer"                   $PEER_FQDN
        printf "%-60s : %s\n" "     > Site ID"              $PEER_ID
        printf "%-60s : %s\n" "     > Loopback interface"   $PEER_OUTSIDE_IP

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

    if [[ $TUNNEL_MODE == "WireGuard" ]]; then
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
    else
        printf "\n   - Check IPSec RSA-keys\n"
        Cfg_Cmd "set vpn rsa-keys local-key file /config/ipsec.d/rsa-keys/localhost.key"
        Cfg_Cmd "set vpn rsa-keys rsa-key-name $PEER_FQDN rsa-key $PEER_RSA_PUB"

        printf "\n   - Create IPSec tunnel\n"
        Cfg_Cmd "set vpn ipsec esp-group ESP0 compression disable"
        Cfg_Cmd "set vpn ipsec esp-group ESP0 lifetime 3600"
        Cfg_Cmd "set vpn ipsec esp-group ESP0 mode tunnel"
        Cfg_Cmd "set vpn ipsec esp-group ESP0 pfs enable"
        Cfg_Cmd "set vpn ipsec esp-group ESP0 proposal 1 encryption aes128"
        Cfg_Cmd "set vpn ipsec esp-group ESP0 proposal 1 hash sha1"
        Cfg_Cmd "set vpn ipsec ike-group IKE0 ikev2-reauth no"
        Cfg_Cmd "set vpn ipsec ike-group IKE0 key-exchange ikev1"
        Cfg_Cmd "set vpn ipsec ike-group IKE0 lifetime 28800"
        Cfg_Cmd "set vpn ipsec ike-group IKE0 proposal 1 dh-group 14"
        Cfg_Cmd "set vpn ipsec ike-group IKE0 proposal 1 encryption aes128"
        Cfg_Cmd "set vpn ipsec ike-group IKE0 proposal 1 hash sha1"

        Cfg_Cmd "set vpn ipsec ike-group IKE0 dead-peer-detection action restart"
        Cfg_Cmd "set vpn ipsec ike-group IKE0 dead-peer-detection interval 30"
        Cfg_Cmd "set vpn ipsec ike-group IKE0 dead-peer-detection timeout 120"

        Cfg_Cmd "set vpn ipsec ipsec-interfaces interface $vpn_if_name"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  authentication id $LOCAL_FQDN"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  authentication mode rsa"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  authentication remote-id $PEER_FQDN "
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  authentication rsa-key-name $PEER_FQDN"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  connection-type respond"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  description 'gre over ipsec'"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  ike-group IKE0"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  ikev2-reauth inherit"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  local-address any"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  tunnel 0 esp-group ESP0"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  tunnel 0 local prefix $LOCAL_OUTSIDE_IP/32"
        Cfg_Cmd "set vpn ipsec site-to-site peer $PEER_FQDN  tunnel 0 remote prefix $PEER_OUTSIDE_IP/32"

        printf "\n   - Configure Firewall & NAT exclude\n"
 
        if [[ $ROUTER_TYPE == "VyOS" ]]; then
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1000 action 'accept'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1000 description 'ipsec-ike/nat'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1000 destination port '500,4500'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1000 protocol 'udp'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1000 log disable"

            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1001 action 'accept'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1001 description 'ipsec esp'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1001 protocol 'esp'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1001 log disable"

            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1002 action 'accept'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1002 description 'gre over ipsec'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1002 protocol 'esp'"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1002 log disable"

            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1003 action accept"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1003 description ipsec"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1003 destination address $LOCAL_OUTSIDE_IP/32"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1003 log disable"
            Cfg_Cmd "set firewall name INTERNET_ROUTER rule 1003 ipsec match-ipsec"

            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 action accept"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 description ipsec"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 destination address $LOCAL_OUTSIDE_IP/32"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 log disable"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 ipsec match-ipsec"

            Cfg_Cmd "set nat source rule 1 exclude"
            Cfg_Cmd "set nat source rule 1 outbound-interface $vpn_if_name"
            Cfg_Cmd "set nat source rule 1 source address $LOCAL_OUTSIDE_IP/32"
            Cfg_Cmd "set nat source rule 1 description 'gre over ipsec'"
        else
            Cfg_Cmd "set vpn ipsec auto-firewall-nat-exclude enable" 

            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 action accept"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 description 'allow gre over ipsec'"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 destination address $LOCAL_OUTSIDE_IP/32"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 log disable"
            Cfg_Cmd "set firewall name INTERNET_OFFICE rule 1003 ipsec match-ipsec"
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

    Cfg_Comment "   - Add interface [$TUN_NAME] to office zone \n"    
    Cfg_Cmd "set zone-policy zone OFFICE interface $TUN_NAME &> /dev/null"

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
# Add a local network & setup security zone
# Platform: 
#      EdgeOS/VyOS
# ****************************************************************************
function Add_Local_Network() {


    printf  "\n**********************************************************************\n"
    printf    "*                          Add a local network                       *\n" 
    printf    "**********************************************************************\n"


}



# ****************************************************************************
# EdgeRouter Setup menu & functions
# Usage:
#      EdgeRouter_Menu
# ****************************************************************************
function EdgeRouter_Menu() {

    # Root directory of configuration files
    CONFIG_ROOT="/config"
    
    # Edgerouter or VyOS
    SWITCHIF="N"
    # Read hardware ROUTER_MODEL and firmware version
    while read -r FIELD1 FIELD2 FIELD3; do
        if [[ $FIELD1  == "Version:" ]]; then
            ROUTER_TYPE="EdgeRouter"
            VERSION=$FIELD2
            RELEASE=${VERSION%%.*}
        elif [[ ${FIELD1}${FIELD2}  == "HWmodel:" ]]; then 
            ROUTER_MODEL="$FIELD3"
            case $ROUTER_MODEL in
                "EdgeRouter X 5-Port" | "EdgeRouter 10X")
                    UBNT_HWID=e50
                    SWITCHIF="Y"
                    ;;
                "EdgeRouter PoE 5-Port")
                    UBNT_HWID=e100
                    SWITCHIF="Y"
                    ;;
                "EdgeRouter 8-Port")
                    UBNT_HWID=e200
                    ;;
                "EdgeRouter 4" | "EdgeRouter 6P")
                    UBNT_HWID=e300
                    ;;
                "EdgeRouter 12" | "EdgeRouter 12P")
                    UBNT_HWID=e300
                    SWITCHIF="Y"
                    ;;
                *)
                    printf  "\n    **** Unsupported ROUTER_MODEL: $ROUTER_MODEL, exits now\n\n"
                    exit 0
                    ;;  
            esac
        elif [[ ${FIELD1}${FIELD2}  == "HWS/N:" ]]; then 
            SERIALNO=$FIELD3
        elif [[ ${FIELD1}${FIELD2}  == "ReleaseTrain:" ]]; then 
            ROUTER_MODEL=$FIELD3                   # use release train as VyOS ROUTER_MODEL
        fi
    done < <($ROUTER_RUNCMD show version)

    printf  "\n o Device information\n"
    printf  "%-60s : %s\n" "   - Type"      "$ROUTER_TYPE"
    printf  "%-60s : %s\n" "   - Model"     "$ROUTER_MODEL"
    printf  "%-60s : %s\n" "   - Version"   "$VERSION"

    Scan_Network_Ports

    while [[ true ]]; do
        if ! Load_Localhost_Cfg; then
            printf "\n   *** This Router is not initialized ***\n"
            if Ask_Confirm ">>> Do you want to initialize it?" "Y"; then
                EdgeOS_Initialization
                continue
            else
                printf "\n   *** Thank you for use this script **** \n\n"
                exit 0
            fi
        fi

        if [[ $CFG_VER != $SCRIPT_VERSION ]]; then
            DEFAULT_ACTION="9"
        else
            DEFAULT_ACTION="0"
        fi

        # main menu
        printf   "\n\n o Main menu\n"
        printf   " ----------------------------------------------------------------------\n"
#        printf   "   1. Add a local network\n"
        printf   "   2. Connect another site with GRE tunnel\n"
        printf   "   3. Setup Roadwarrior VPN\n"
        printf   "   4. Jail-break Great firewall\n"
        printf   "   --------------------------------------------------------------------\n"
        printf   "   9. Re-intialize this router\n"
        printf   "   0. Exit\n"

        printf   "\n%37s %22s : " ">>> Your choice" "[$DEFAULT_ACTION]"  
        read INPUT
        INPUT=${INPUT:-$DEFAULT_ACTION}

        case "$INPUT" in
            "1")
                Add_Local_Network
                ;;
            "2")
                Connect_Site
                ;;
            "3")
                EdgeOS_StrongSwan_Setup
                ;;
            "9")
                EdgeOS_Initialization
                ;;
            "0")
                break
                ;;
            *)
            printf   "\n **** Feature not implemented yet ****\n"
            ;;
        esac
    done
}

# ****************************************************************************
# VyOS Setup menu & functions
# Usage:
#      EdgeRouter_Menu
# ****************************************************************************
function VyOS_Menu() {

    # Root directory of configuration files
    CONFIG_ROOT="/config"
    ROUTER_TYPE="VyOS"

    # Read version information
    # Read hardware ROUTER_MODEL and firmware version
    while read -r FIELD1 FIELD2 FIELD3; do
        if [[ $FIELD1  == "Version:" ]]; then
            VERSION=$FIELD3
        elif [[ ${FIELD1}${FIELD2}  == "ReleaseTrain:" ]]; then 
            ROUTER_MODEL=$FIELD3                   # use release train as VyOS ROUTER_MODEL
        fi
    done < <($ROUTER_RUNCMD show version)

    printf  "\n o Device information\n"
    printf  "%-60s : %s\n" "   - Model"     "VyOS"
    printf  "%-60s : %s\n" "   - Release"   "$ROUTER_MODEL"
    printf  "%-60s : %s\n" "   - Version"   "$VERSION"

    Scan_Network_Ports

    while [[ true ]]; do
        if ! Load_Localhost_Cfg; then
            echo ""
            if Ask_Confirm ">>> New router found, initialize it?" "Y"; then
                VyOS_Initialization
                continue
            else
                printf "\n   *** Thank you for use this script **** \n\n"
                exit 0
            fi
        fi

        if [[ $CFG_VER != $SCRIPT_VERSION ]]; then
            DEFAULT_ACTION="9"
        else
            DEFAULT_ACTION="0"
        fi

        # main menu
        printf   "\n\n o Main menu\n"
        printf   " ----------------------------------------------------------------------\n"
#        printf   "   1. Add a local network\n"
        printf   "   2. Connect another site with GRE tunnel\n"
        printf   "   3. Setup Roadwarrior VPN\n"
#        printf   "   4. Jail-break Great firewall\n"
        printf   "   --------------------------------------------------------------------\n"
        printf   "   9. Re-intialize VyOS\n"
        printf   "   0. Exit\n"

        printf   "\n%37s %22s : " ">>> Your choice" "[$DEFAULT_ACTION]"  
        read INPUT
        INPUT=${INPUT:-$DEFAULT_ACTION}

        case "$INPUT" in
#            "1")
#                Add_Local_Network
#                ;;
            "2")
                Connect_Site
                ;;
            "3")
                VyOS_StrongSwan_Setup
                ;;
            "9")
                VyOS_Initialization
                ;;
            "0")
                break
                ;;
            *)
            printf   "\n **** Feature not implemented yet ****\n"
            ;;
        esac
    done
}


# ****************************************************************************
# Main script
# ****************************************************************************

printf  "\n**********************************************************************\n"
printf    "*                    EdgeOS/VyOS setup script v%-3s                   *\n" "$SCRIPT_VERSION"
printf    "*            (c) Jackson Tong & Creekside Networks LLC 2021          *\n"
printf    "*              Usage: ssh -t ip \"\$(\<./router-setup.sh)\"             *\n"
printf    "**********************************************************************\n"

#check os
OS_TYPE=$(cat /etc/os-release | grep ^NAME= | cut -d "=" -f2-)

if [[ $OS_TYPE == "\"Debian GNU/Linux\"" ]]; then
    if [[ ! -z $(uname -r | grep UBNT) ]]; then
        EdgeRouter_Menu
    elif [[ ! -z $(uname -r | grep vyos) ]]; then
        VyOS_Menu
    else
        printf "\n   *** Unsupported OS type [$OS_TYPE] ***\n\n"
        exit 1            
    fi
else
    printf "\n   *** Unsupported OS type [$OS_TYPE] ***\n\n"
    exit 1
fi

printf   "\n **** All done, thank you ****\n\n"

exit 0


