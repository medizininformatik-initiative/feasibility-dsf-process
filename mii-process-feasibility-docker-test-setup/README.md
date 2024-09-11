# Docker Test Setup

This directory contains a `docker-compose.yml` describing a ZARS part and multiple different example setups regarding a
DIC. These example setups shall illustrate different supported functionalities of this plugin and their corresponding
configuration settings.

### Custom FHIR Server Image

Before you can start any site, you have to run maven in order to build plugins, certificates and test data:

```sh
./rebuild.sh
```

If you use Linux, you have to set some rights on directories where containers should write into:

```sh
./set-rights.sh
```

If you changed a lot of things and like to start fresh, it's a good idea to delete all volumes:

```sh
docker-compose down -v
```

Add the following entries to `/etc/hosts`:

```
127.0.0.1       zars
127.0.0.1       dic-1
127.0.0.1       dic-2
127.0.0.1       dic-3
127.0.0.1       dic-4
```

After that, you can start the ZARS FHIR Inbox using:

```sh
docker-compose up -d zars-fhir-app && docker-compose logs -f zars-fhir-app
```

After that, you can query the [CapabilityStatement][1] of the inbox:

```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s https://zars/fhir/metadata |\
  jq '.software, .implementation'
```

As you can see in the above command, a port mapping is created on port 443. In order to be able to access not only the
zars, but also the other sites, you have to use the domain name `zars` here. With [curl][2], you can specify a custom
resolver, which will resolve the host `zars` to localhost. An alternative would be to create an entry in
your `/etc/hosts`. The next line in the command is about Client and CA Certificates.

After that, you can stop the ZARS FHIR Inbox log output and start the ZARS Business Process Engine in the same terminal:

```sh
docker-compose up -d zars-bpe-app && docker-compose logs -f zars-fhir-app zars-bpe-app
```

After starting the ZARS, you can start the DIC-1 FHIR Inbox using:

```sh
docker-compose up -d dic-1-fhir-app && docker-compose logs -f dic-1-fhir-app
```

The following command should return the CapabilityStatement:

```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s https://dic-1/fhir/metadata |\
  jq '.software, .implementation'
```

After that, you can stop the DIC-1 FHIR Inbox log output and start the DIC-1 Business Process Engine and Blaze in the same terminal:

```sh
docker-compose up -d dic-1-bpe-app && docker-compose logs -f dic-1-fhir-app dic-1-bpe-app
```

Continue with other DIC as you see fit.

After that we can POST the first Task to the ZARS:

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

After exporting the Task ID to $TASK_ID, you can fetch the task:

```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s "https://zars/fhir/Task/${TASK_ID}" |\
  jq .
```

The task should be completed and contain an output with the reference of the MeasureReport created.

## Debugging

You can use the following env var and port mapping to enable debugging of one container:

```
ports:
- 5005:5005
environment:
  EXTRA_JVM_ARGS: -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005
```

Quick restart of the debugging stack:
```sh
docker-compose down -v 

docker-compose up -d zars-fhir-app 
sleep 3

docker-compose up -d zars-bpe-app 
sleep 2

docker-compose up -d dic-2-fhir-app 
sleep 3

docker-compose up -d dic-2-bpe-app 
```

Start Debugging 'remote dic_2_bpe debugging'

After that we can POST the first Task to the ZARS:

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

After exporting the Task ID to $TASK_ID, you can fetch the task:

```sh
curl \
  --cacert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/ca/testca_certificate.pem \
  --cert-type P12 \
  --cert ../mii-process-feasibility-tools/mii-process-feasibility-test-data-generator/cert/Webbrowser_Test_User/Webbrowser_Test_User_certificate.p12:password \
  -H accept:application/fhir+json \
  -s "https://zars/fhir/Task/${TASK_ID}" |\
  jq .
```


[1]: <https://www.hl7.org/fhir/capabilitystatement.html>

[2]: <https://curl.se>
   