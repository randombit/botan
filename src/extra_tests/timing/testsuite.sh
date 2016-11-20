#!/bin/sh

cd timing-tests
make
./main

zipdate=$(date +%d-%H-%M)
zipfile="${zipdate}-results.zip"
zip -r $zipfile results

cd ..
cd mona-timing-report

for dir in ../timing-tests/results/*; 
do
    echo "Working in directory: " $dir
    for file in $dir/*;
    do
        echo "Creating report for: " $file
        java -jar ReportingTool.jar --inputFile=$file --name=$file --lowerBound=0.4 --upperBound=0.5
        rm $file
    done
done
