#!/bin/bash

echo $FLAG > /flag
unset FLAG

java -Xmx256m -jar /app/demo-0.0.1-SNAPSHOT.jar
