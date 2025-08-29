#!/bin/bash
# ****************************************************************************
# VyOS/EdgeRouter configuration utility v2
# (c) Jackson Tong, Creekside Networks LLC.
# ****************************************************************************

SSH_OPTIONS="-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"
#!/bin/bash
# ****************************************************************************
# VyOS/EdgeRouter configuration utility v2
# (c) Jackson Tong, Creekside Networks LLC.
# ****************************************************************************

cmd_usage() {
	cat >&2 <<-_EOF

  Usage: $PROGRAM [ OPTIONS ] [user@]router

    router: router's FQDN or IP address  
    -p: port
    -h: Print this help

    written by: Jackson Tong 2022 

	_EOF
}

port=""

while getopts 'p:P:h:' option
do
    case "${option}" in
        p|P) 
            port=${OPTARG};;
        h|H)
            cmd_usage
            exit 0;;
        *)
            exit 1;;
    esac
done

# Remove all options passed by getopts options
shift "$(($OPTIND -1))"

# Reading router fqdn/ip
if [ ! -z $1 ]; then
    router=$1
else
    echo "No router FQDN/IP is given."
    exit 1
fi

if [[ ${router%@*} == $router ]]; then
    userid="jtong"
else
    userid=${router%@*}
    router=${router#*@}
fi

CONFIG_DIR="/Users/jtong/project/router/template/user-data"

if [[ $port != "" ]]; then
    SSH_OPTIONS=$SSH_OPTIONS -p $port
fi

if [[ ! -d ${CONFIG_DIR} ]]; then
    echo "   *** Can not find source: ${CONFIG_DIR}, exits"
    exit
fi

echo "upload dnsmasq-ipset folder to ${router}"
scp -r $SSH_OPTIONS $CONFIG_DIR $userid@$router:/tmp
echo "Move uploaded files to destiantion"
ssh $SSH_OPTIONS "$userid@$router" "sudo cp -r /tmp/user-data /config"
echo "Restart DNSMASQ"
ssh $SSH_OPTIONS "$userid@$router" "sudo systemctl restart dnsmasq && sleep 1 && sudo systemctl status dnsmasq"

