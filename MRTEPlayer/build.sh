#!/bin/bash

cur_dir=$(dirname `realpath $0`)
if [[ -z $MRTE_HOME ]]; then
	MRTE_HOME=${cur_dir%/*}
fi

MRTE_PLAYER_HOME=$MRTE_HOME/MRTEPlayer

TARGETPATH=$MRTE_PLAYER_HOME/build
CLASSPATH=.

for jar in $MRTE_PLAYER_HOME/lib/*.jar;
do
    CLASSPATH=$CLASSPATH:$jar
done

pushd $MRTE_PLAYER_HOME/src
echo "javac -cp $CLASSPATH mrte/*.java -d $TARGETPATH"
javac -cp $CLASSPATH mrte/*.java -d $TARGETPATH
popd

