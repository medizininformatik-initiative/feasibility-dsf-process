```xml
<!--Distribution-->
<extension url="http://dsf.dev/fhir/StructureDefinition/extension-process-authorization">
    <extension url="message-name">
        <valueString value="feasibilityRequestMessage"/>
    </extension>
    <extension url="task-profile">
        <valueCanonical
                value="http://medizininformatik-initiative.de/fhir/StructureDefinition/feasibility-task-request|#{version}"/>
    </extension>
    <extension url="requester">
        <valueCoding>
            <extension
                    url="http://dsf.dev/fhir/StructureDefinition/extension-process-authorization-parent-organization-role">
                <extension url="parent-organization">
                    <valueIdentifier>
                        <system value="http://dsf.dev/sid/organization-identifier"/>
                        <value value="distributed-org.de"/>
                    </valueIdentifier>
                </extension>
                <extension url="organization-role">
                    <valueCoding>
                        <system value="http://dsf.dev/fhir/CodeSystem/organization-role"/>
                        <code value="HRP"/>
                    </valueCoding>
                </extension>
            </extension>
            <system value="http://dsf.dev/fhir/CodeSystem/process-authorization"/>
            <code value="REMOTE_ALL"/>
        </valueCoding>
    </extension>
    <extension url="requester">
        <valueCoding>
            <extension url="http://dsf.dev/fhir/StructureDefinition/extension-process-authorization-parent-organization-role-practitioner">
                <extension url="parent-organization">
                    <valueIdentifier>
                        <system value="http://dsf.dev/sid/organization-identifier" />
                        <value value="Test_Broker" />
                    </valueIdentifier>
                </extension>
                <extension url="organization-role">
                    <valueCoding>
                        <system value="http://dsf.dev/fhir/CodeSystem/organization-role" />
                        <code value="HRP" />
                    </valueCoding>
                </extension>
                <extension url="practitioner-role">
                    <valueCoding>
                        <system value="http://dsf.dev/fhir/CodeSystem/practitioner-role" />
                        <code value="DSF_ADMIN" />
                    </valueCoding>
                </extension>
            </extension>
            <system value="http://dsf.dev/fhir/CodeSystem/process-authorization" />
            <code value="REMOTE_ALL" />
        </valueCoding>
    </extension>
    <extension url="recipient">
        <valueCoding>
            <extension
                    url="http://dsf.dev/fhir/StructureDefinition/extension-process-authorization-parent-organization-role">
                <extension url="parent-organization">
                    <valueIdentifier>
                        <system value="http://dsf.dev/sid/organization-identifier"/>
                        <value value="Test_Broker"/>
                    </valueIdentifier>
                </extension>
                <extension url="organization-role">
                    <valueCoding>
                        <system value="http://dsf.dev/fhir/CodeSystem/organization-role"/>
                        <code value="HRP"/>
                    </valueCoding>
                </extension>
            </extension>
            <system value="http://dsf.dev/fhir/CodeSystem/process-authorization"/>
            <code value="LOCAL_ALL"/>
        </valueCoding>
    </extension>
</extension>
        <!--    Distribution End)-->
```