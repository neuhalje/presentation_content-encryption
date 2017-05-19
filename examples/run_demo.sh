#!/usr/bin/env bash

ASSEMBLY=examples-1.0.0
LOCATION=./build

DRIVER_CLASS=name.neuhalfen.projects.crypto.contentencryption.example.Main

DEST=/tmp/encryption-example-$$

[ -d "${DEST}" ] && rm -rf "${DEST}" 
mkdir $DEST || exit 1
echo Writing results into \"$DEST\"

[ -f ./build/libs/${ASSEMBLY}.jar ] ||  ./gradlew installDist

CP=${LOCATION}/libs/${ASSEMBLY}.jar
for JAR in ${LOCATION}/install/examples/lib/*.jar
do
   CP=${CP}:${JAR}
done

time java -cp ${CP} \
   ${DRIVER_CLASS}


echo
echo Results in $DEST
