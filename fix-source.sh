#!/bin/bash

for filePath in $(find ./src/main/java -type f); do
	packageRaw=$(head ${filePath} -n1 | cut -d ' ' -f2)
	packageNL=${packageRaw/;/.}
	packageORG=${packageNL/nl.first8/org}
	filename=$(basename -- ${filePath} | cut -d '.' -f1)
	find $(pwd)/src/main/java -type f -exec sed -i 's/${packageORG}${filename}/${packageNL}${filename}/g' {} \;
done
