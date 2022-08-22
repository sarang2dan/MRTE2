#!/bin/bash

cur_dir=$(dirname `realpath $0`)
if [[ -z $MRTE_HOME ]]; then
	MRTE_HOME=${cur_dir%/*}
fi

sudo $MRTE_HOME/bin/MRTECollector \
  -mongouri='mongodb://mongo-queue-db:30000?connect=direct' \
  -mongodb="mrte" \
  -mongocollection="mrte" \
  -threads=5 \
  -fastparsing=true \
  -interface=en0 \
  -debug=true \
  -verbose=true \
  -mysqluri='mrte2:mrte2@tcp(127.0.0.1:3306)/'

