#!/bin/bash

cur_dir=$(dirname `realpath $0`)
if [[ -z $MRTE_HOME ]]; then
	MRTE_HOME=${cur_dir%/*}
fi

MY_ACCOUNT=`whoami`
MY_GRPS=`groups`
SUDO=sudo

# sudo를 실행하기 위해, root 계정 혹은 그룹을 확인
if [[ "$MY_ACCOUNT" == "root" ]];
then
	SUDO=
else
	if [[ "$MY_GRPS" == *"root"* ]];
	then
		SUDO=
	fi
fi

$SUDO $MRTE_HOME/bin/MRTECollector \
  -mongouri="mongodb://$MRTE_MONGODB_ADDR?connect=direct" \
  -mongodb="mrte" \
  -mongocollection="mrte" \
  -threads=5 \
  -fastparsing=true \
  -interface=bridge100 \
  -mysqluri='mrte2:mrte2@tcp(127.0.0.1:3306)/'

