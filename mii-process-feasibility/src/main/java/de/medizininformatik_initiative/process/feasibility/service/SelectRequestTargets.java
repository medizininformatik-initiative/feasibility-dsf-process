package de.medizininformatik_initiative.process.feasibility.service;

import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.service.OrganizationProvider;
import dev.dsf.bpe.v1.variables.Variables;
import dev.dsf.fhir.client.FhirWebserviceClient;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Bundle.BundleEntryComponent;
import org.hl7.fhir.r4.model.Bundle.SearchEntryMode;
import org.hl7.fhir.r4.model.Endpoint;
import org.hl7.fhir.r4.model.Organization;
import org.hl7.fhir.r4.model.OrganizationAffiliation;
import org.hl7.fhir.r4.model.Reference;
import org.hl7.fhir.r4.model.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REFERENCE;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.DIC;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.HRP;

public class SelectRequestTargets extends AbstractServiceDelegate {

    private static final Logger logger = LoggerFactory.getLogger(SelectRequestTargets.class);

    public SelectRequestTargets(ProcessPluginApi api) {
        super(api);
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        var organizationProvider = api.getOrganizationProvider();
        var client = api.getFhirWebserviceClientProvider().getLocalWebserviceClient();
        var parentOrganization = getLocalParentOrganization(organizationProvider, client);
        var targets = organizationProvider
                .getOrganizations(parentOrganization.getIdentifierFirstRep(), DIC)
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
        targets.forEach(t -> logger.debug(t.getOrganizationIdentifierValue()));
        variables.setTargets(variables.createTargets(targets));
        variables.setString("measure-id", client.getBaseUrl() + getMeasureId(variables.getStartTask()));
    }

    private Organization getLocalParentOrganization(OrganizationProvider organizationProvider,
                                                    FhirWebserviceClient client) {
        var localOrganization = organizationProvider.getLocalOrganization()
                .orElseThrow(() -> new IllegalStateException("No local organization configured."));
        var localOrganizationIdentifier = localOrganization.getIdentifierFirstRep().getValue();

        Bundle result = client.search(OrganizationAffiliation.class,
                Map.of("active", List.of("true"),
                        "participating-organization:identifier", List.of(localOrganizationIdentifier),
                        "role", List.of(HRP.getCode()),
                        "_include", List.of("OrganizationAffiliation:primary-organization")));
        List<Organization> parentOrganizations = result.getEntry().stream().filter(BundleEntryComponent::hasSearch)
                .filter(e -> SearchEntryMode.INCLUDE.equals(e.getSearch().getMode()))
                .filter(BundleEntryComponent::hasResource)
                .map(BundleEntryComponent::getResource)
                .filter(Organization.class::isInstance)
                .map(Organization.class::cast)
                .filter(Organization::getActive)
                .toList();

        if (parentOrganizations.size() == 1) {
            return parentOrganizations.get(0);
        } else {
            throw new IllegalStateException(
                    "Local organization '%s' has role '%s' in %d parent organizations %s, but must be exactly 1."
                            .formatted(localOrganizationIdentifier, HRP.getCode(), parentOrganizations.size(),
                                    parentOrganizations));
        }
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
