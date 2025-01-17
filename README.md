# Feasibility Processes

Business processes for the MII feasibility project as plugins for the [Data Sharing Framework][1].

## Build

Prerequisite: Java 17, Maven >= 3.6

Build the project from the root directory of this repository by executing the following command.

```sh
mvn clean package
```

## Usage

For running the feasibility processes you need a working and up-to-date DSF instance by following the
[DSF installation guide][2]. The processes are deployed to the DSF BPE component by adding the JAR file of the latest
stable release of the feasibility process plugin to your `process` folder of the DSF BPE. The processes have to be
configured as outlined in the configuration section in the [feasibility process overview][3].

### Update

For updating the feasibility processes to the latest stable version do the following steps:

  * stop your running DSF BPE instance
  * replace the existing JAR file of the feasibility processes plugin in your `process` folder of you DSF BPE with the JAR
    file of the latest stable release of the feasibility process plugin
  * compare and adjust your existing processes configuration to the configuration options documented in the
    [feasibility process overview][3]

You can test the processes workflows locally by following the [README][4]] in the
`mii-process-feasibility-docker-test-setup` directory.

## Edit

You should edit the *.bpmn files only with the standalone [Camunda Modeler][5], because of different
formatting of the bpmn tools and plugins.

## License

Copyright 2021 Medizininformatik-Initiative

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "
AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.

[1]: <https://dsf.dev>
[2]: <https://dsf.dev/stable/maintain/install.html>
[3]: <mii-process-feasibility/README.md#configuration>
[4]: <mii-process-feasibility-docker-test-setup/README.md>
[5]: <https://camunda.com/download/modeler/>
