package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.FeasibilitySettings;
import de.medizininformatik_initiative.process.feasibility.FeasibilitySettings.NetworkSettings;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.service.OrganizationProvider;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Identifier;
import org.hl7.fhir.r4.model.Organization;
import org.hl7.fhir.r4.model.Reference;
import org.hl7.fhir.r4.model.Task;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.HRP;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_EVALUATION_OBFUSCATION;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_REQUESTER_PARENT_ORGANIZATION;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SetupEvaluationSettingsTest {

    @Mock private DelegateExecution execution;
    @Mock private Variables variables;
    @Mock private ProcessPluginApi api;
    @Mock private OrganizationProvider organizationProvider;
    @Mock private Task task;


    @Test
    public void testDoExecute() throws Exception {
        var networkId = "foo";
        var requesterId = "foo.bar";
        var orgName = "foo-12:00:25";
        var orgIdentifier = new Identifier();
        var requester = new Organization().setName(orgName).setIdentifier(List.of(orgIdentifier));
        var obfuscate = true;
        var network = new NetworkSettings(obfuscate, null, null);
        var settings = new FeasibilitySettings(Map.of(networkId, network), null);
        var service = new SetupEvaluationSettings(settings, api);
        when(api.getVariables(execution)).thenReturn(variables);
        when(variables.getStartTask()).thenReturn(task);
        when(task.getRequester()).thenReturn(new Reference(requesterId).setIdentifier(orgIdentifier));
        when(api.getOrganizationProvider()).thenReturn(organizationProvider);
        when(organizationProvider.getOrganization(orgIdentifier)).thenReturn(Optional.of(requester));
        when(organizationProvider.getOrganizations(networkId, HRP)).thenReturn(List.of(requester));

        service.execute(execution);
        verify(variables).setString(VARIABLE_REQUESTER_PARENT_ORGANIZATION, networkId);
        verify(variables).setBoolean(VARIABLE_EVALUATION_OBFUSCATION, obfuscate);
    }

}
