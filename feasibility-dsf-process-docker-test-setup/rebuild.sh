#!/usr/bin/env sh

mvn -f ../feasibility-dsf-process/pom.xml clean package
mvn -f ../feasibility-dsf-process-tools/feasibility-dsf-process-test-data-generator/pom.xml clean package
