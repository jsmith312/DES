#!/bin/bash

# compile or run project, assume gnu.getopt.jar in current directory
case "$1" in
	-c|"-C")
        javac -cp "gnu.getopt.jar:." DES_Skeleton.java SBoxes.java
        ;;

	-r|"-R")
        java -cp "gnu.getopt.jar:." DES_Skeleton $2 $3 $4 $5 $6 $7
        ;;

	-cr|"-CR")
        javac -cp "gnu.getopt.jar:." DES_Skeleton.java SBoxes.java &&
		java -cp "gnu.getopt.jar:." DES_Skeleton $2 $3 $4 $5 $6 $7
        ;;
    *)
        java -cp "gnu.getopt.jar:." DES_Skeleton $1 $2 $3 $4 $5 $6
esac