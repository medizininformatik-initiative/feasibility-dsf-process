package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.FeasibilitySettings;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Organization;
import org.springframework.beans.factory.InitializingBean;

import java.util.Objects;
import java.util.stream.Collectors;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.HRP;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_EVALUATION_OBFUSCATION;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_REQUESTER_PARENT_ORGANIZATION;

public class SetupEvaluationSettings extends AbstractServiceDelegate
        implements InitializingBean {

    private final FeasibilitySettings settings;

    public SetupEvaluationSettings(FeasibilitySettings settings, ProcessPluginApi api) {
        super(api);
        this.settings = settings;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Objects.requireNonNull(settings, "settings");
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        var requester = getRequesterOrganization(variables);
        var parentId = getParentOrganizationId(requester);

        variables.setString(VARIABLE_REQUESTER_PARENT_ORGANIZATION, parentId);
        variables.setBoolean(VARIABLE_EVALUATION_OBFUSCATION, settings.networks().get(parentId).obfuscate());
    }

    private Organization getRequesterOrganization(Variables variables) {
        var orgIdentifier = variables.getStartTask().getRequester().getIdentifier();

        return api.getOrganizationProvider().getOrganization(orgIdentifier)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Task requester organization with identifer '%s' is unknown.".formatted(orgIdentifier)));
    }

    private String getParentOrganizationId(Organization requester) {
        var parentIds = settings.networks().keySet();
        return parentIds.parallelStream()
                .collect(Collectors.toMap(p -> p, p -> api.getOrganizationProvider().getOrganizations(p, HRP)))
                .entrySet()
                .stream()
                .filter(e -> e.getValue().stream().anyMatch(o -> o.equalsShallow(requester)))
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException(
                        "None of the configured networks %s contain the task requester organization (%s) with role '%s'."
                                .formatted(parentIds, requester.getIdentifierFirstRep().getValue(), HRP.getCode())))
                .getKey();
    }
}
