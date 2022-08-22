#!/bin/bash

cur_dir=$(dirname `realpath $0`)
if [[ -z $MRTE_HOME ]]; then
	MRTE_HOME=${cur_dir%/*}
fi

MRTE_PLAYER_HOME=$MRTE_HOME/MRTEPlayer

LOG_DATE=`date +%m%d_%H%M%S` # MonthDay_HHMMSS
LOG_DIR=$MRTE_PLAYER_HOME/log/$LOG_DATE
mkdir -p $LOG_DIR

CLASSPATH=.:$MRTE_PLAYER_HOME/build/
for jar in $MRTE_PLAYER_HOME/lib/*.jar; do
    CLASSPATH=$CLASSPATH:$jar
done


# for Mac
if [[ `uname -s` -eq "Darwin" ]];
then
JAVA_VM_OPTS="
  -XX:NewSize=1024M \
  -XX:SurvivorRatio=3 \
  -XX:MaxTenuringThreshold=3 \
  -Xlog:gc* \
  -Xlog:gc:$LOG_DIR/mrte_player_gc.log \
  -Xmx2G \
  -Xms2G"
else
# opts
JAVA_VM_OPTS="
  -XX:+UseParNewGC \
  -XX:+UseConcMarkSweepGC \
  -XX:NewSize=1024M \
  -XX:SurvivorRatio=3 \
  -XX:MaxTenuringThreshold=3 \
  -XX:+CMSParallelRemarkEnabled \
  -XX:CMSInitiatingOccupancyFraction=70 \
  -XX:+UseCMSInitiatingOccupancyOnly \
  -XX:+PrintGCDetails \
  -XX:+PrintGCDateStamps \
  -XX:+PrintTenuringDistribution \
  -XX:+PrintGCApplicationStoppedTime \
  -Xloggc:$LOG_DIR/mrte_player_gc.log \
  -XX:+UseGCLogFileRotation \
  -XX:NumberOfGCLogFiles=10 \
  -XX:GCLogFileSize=20M \
  -Xmx2G \
  -Xms2G"
fi

## only redirect error log to file (error.log)
java \
  $JAVA_VM_OPTS \
  -cp $CLASSPATH mrte.MRTEPlayer \
  --mysql_url='jdbc:mysql://127.0.0.1:3306/mysqlslap?user=mrte2&password=mrte2' \
  --mysql_init_connections=50 \
  --mysql_default_db="mysqlslap" \
  --mongo_url="mongodb://$MRTE_MONGODB_ADDR/mrte?connectTimeoutMS=300000&authSource=admin" \
  --mongo_db="mrte" \
  --mongo_collectionprefix="mrte" \
  --mongo_collections=5 \
  --slow_query_time=100 \
  --verbose=true 2> $LOG_DIR/error.log


## Connect mongodb without auth
## --mongo_url="mongodb://mongo-queue-db:30000/mrte?connectTimeoutMS=300000" \
## Connect mongodb with auth
## --mongo_url="mongodb://username:password@mongo-queue-db:30000/mrte?connectTimeoutMS=300000&authSource=admin" \
