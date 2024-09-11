
# Build maven Project

```sh
mvn -f ../pom.xml clean install -DskipTests=true
```

# Quick restart of the debugging the broker-bpe-app and broker-dic-5-bpe-app stack

```sh
docker-compose down -v  

docker-compose -f docker-compose.yml up -d zars-fhir-app 
sleep 3

docker-compose -f docker-compose.yml up -d zars-bpe-app 

docker-compose -f docker-compose.yml -f docker-compose.debug.broker-bpe.yml up -d broker-fhir-app
sleep 3

docker-compose -f docker-compose.yml -f docker-compose.debug.broker-bpe.yml up -d broker-bpe-app

docker-compose up -d broker-dic-5-fhir-app 
sleep 2

docker-compose -f docker-compose.yml -f docker-compose.debug.broker-dic-5-bpe.yml up -d broker-dic-5-bpe-app

docker-compose -f docker-compose.yml up -d broker-dic-6-fhir-app
sleep 2

docker-compose -f docker-compose.yml up -d broker-dic-6-bpe-app
```
# Now you can start the debugger with `docker-compose up -d broker-dic-5-bpe-app`.

# After that we can POST the first Task to the ZARS

```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -H content-type:application/fhir+json \
  -d @data/feasibility-bundle.json \
  -s https://zars/fhir/ |\
  jq .
```
# Add Testdata

```sh
# 4 -> 0
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-001.json  http://broker-dic-6-store:8086/fhir
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-002.json  http://broker-dic-6-store:8086/fhir 
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-003.json  http://broker-dic-6-store:8086/fhir
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-004.json  http://broker-dic-6-store:8086/fhir 
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-005.json  http://broker-dic-6-store:8086/fhir
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-006.json  http://broker-dic-6-store:8086/fhir 
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-007.json  http://broker-dic-6-store:8086/fhir
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-008.json  http://broker-dic-6-store:8086/fhir 

# 4 -> 10
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-009.json  http://broker-dic-5-store:8085/fhir
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-010.json  http://broker-dic-5-store:8085/fhir 
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-011.json  http://broker-dic-5-store:8085/fhir
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-012.json  http://broker-dic-5-store:8085/fhir 
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-013.json  http://broker-dic-5-store:8085/fhir
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-014.json  http://broker-dic-5-store:8085/fhir 
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-015.json  http://broker-dic-5-store:8085/fhir
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-016.json  http://broker-dic-5-store:8085/fhir 
curl -H accept:application/fhir+json  -H content-type:application/fhir+json  -d @data/POLAR_TestData-017.json  http://broker-dic-5-store:8085/fhir 
```
# Some CURLs

```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s "https://zars/fhir/Task/${TASK_ID}" |\
  jq .
```
```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s "https://broker/fhir/Task/${TASK_ID}" |\
  jq .
```
```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s "https://broker-dic-5/fhir/Task/${TASK_ID}" |\
  jq .
```
```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s "https://broker/fhir/Organization" |\
  jq .
```
```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s "https://broker-dic-6/fhir/MeasureReport" |\
  jq .
```
```sh
curl \
  -s "http://localhost:8086/fhir/Patient" |\
  jq .
```
```sh
curl \
  -s "http://localhost:8085/fhir/Patient" |\
  jq .
```
```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s "https://broker/fhir/ActivityDefinition" |\
  jq .
```
```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s "https://broker/fhir/Task/712ab360-213a-442a-8013-f1dcb41d6355" |\
  jq .
```


[1]: <https://www.hl7.org/fhir/capabilitystatement.html>

[2]: <https://curl.se>
   