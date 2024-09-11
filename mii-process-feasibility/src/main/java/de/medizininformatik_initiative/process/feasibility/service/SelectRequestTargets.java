package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.EvaluationSettingsProvider;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Target;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REFERENCE;
import static dev.dsf.common.auth.conf.Identity.ORGANIZATION_IDENTIFIER_SYSTEM;

// TODO Überladen
public class SelectRequestTargets extends AbstractServiceDelegate {

    private static final Logger logger = LoggerFactory.getLogger(SelectRequestTargets.class);
    private final EvaluationSettingsProvider evaluationSettingsProvider;

    public SelectRequestTargets(ProcessPluginApi api, EvaluationSettingsProvider evaluationSettingsProvider) {
        super(api);
        this.evaluationSettingsProvider = evaluationSettingsProvider;
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        logger.info("doExecute select request targets");

        var organizationProvider = api.getOrganizationProvider();

        var client = api.getFhirWebserviceClientProvider().getLocalWebserviceClient();
        var parentIdentifier = new Identifier()
                .setSystem(ORGANIZATION_IDENTIFIER_SYSTEM)
                .setValue(this.evaluationSettingsProvider.requestOrganizationIdentifierValue());

        var memberOrganizationRole = new Coding()
                .setSystem("http://dsf.dev/fhir/CodeSystem/organization-role")
                .setCode("DIC");
        List<Target> targets = organizationProvider
                .getOrganizations(parentIdentifier, memberOrganizationRole)
                .stream()
                .filter(Organization::hasEndpoint)
                .filter(Organization::hasIdentifier)
                .map(organization -> {
                    var organizationIdentifier = organization.getIdentifierFirstRep();
                    var path = URI.create(organization.getEndpointFirstRep().getReference()).getPath();
                    var endpoint = client.read(Endpoint.class, path.substring(path.lastIndexOf("/") + 1));
                    return variables.createTarget(organizationIdentifier.getValue(),
                            endpoint.getIdentifierFirstRep().getValue(),
                            endpoint.getAddress(),
                            UUID.randomUUID().toString());
                })
                .collect(Collectors.toList());

        targets.forEach(t -> logger.info("SelectRequestTargets: " + t.getOrganizationIdentifierValue() +
                "\n EndpointUrl: " + t.getEndpointUrl() +
                "\n OrganizationIdentifierValue: " + t.getOrganizationIdentifierValue() +
                "\n EndpointIdentifierValue: " + t.getEndpointIdentifierValue() +
                "\n CorrelationKey: " + t.getCorrelationKey()));

        variables.setTargets(variables.createTargets(targets));

        variables.setString("measure-id",
                api.getFhirWebserviceClientProvider().getLocalWebserviceClient().getBaseUrl()
                        + getMeasureId(variables.getStartTask()));
    }

    private String getMeasureId(Task task) {

        Optional<Reference> measureRef = api.getTaskHelper()
                .getFirstInputParameterValue(task, CODESYSTEM_FEASIBILITY,
                        CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REFERENCE, Reference.class);

        if (measureRef.isPresent()) {
            return measureRef.get().getReference();
        } else {
            logger.error("Task {} is missing the measure reference.", task.getId());
            throw new RuntimeException("Missing measure reference.");
        }
    }
}
