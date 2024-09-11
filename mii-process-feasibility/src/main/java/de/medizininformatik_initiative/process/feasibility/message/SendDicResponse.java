package de.medizininformatik_initiative.process.feasibility.message;

import de.medizininformatik_initiative.process.feasibility.EvaluationSettingsProvider;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractTaskMessageSend;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.Reference;
import org.hl7.fhir.r4.model.Task;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.*;

public class SendDicResponse extends AbstractTaskMessageSend {
    private static final Logger logger = LoggerFactory.getLogger(SendDicResponse.class);
    private static final String INSTANTIATES_CANONICAL_PATTERN_STRING = "(?<processUrl>http[s]{0,1}://(?<domain>(?:(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])\\.)+(?:[a-zA-Z0-9]{1,63}))/bpe/Process/(?<processName>[a-zA-Z0-9-]+))\\|(?<processVersion>\\d+\\.\\d+)$";
    private static final Pattern INSTANTIATES_CANONICAL_PATTERN = Pattern
            .compile(INSTANTIATES_CANONICAL_PATTERN_STRING);
    private final EvaluationSettingsProvider provider;

    public SendDicResponse(ProcessPluginApi api, EvaluationSettingsProvider provider) {
        super(api);
        this.provider = provider;
    }

    @Override
    protected Stream<Task.ParameterComponent> getAdditionalInputParameters(DelegateExecution execution,
                                                                           Variables variables) {
        logger.info("getAdditionalInputParameters send result to requester");

        return Stream.of(api.getTaskHelper()
                .createInput(new Reference().setReference(variables.getString(VARIABLE_MEASURE_REPORT_ID)),
                        CODESYSTEM_FEASIBILITY, CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REPORT_REFERENCE));
    }

    @Override
    protected String getInstantiatesCanonical(DelegateExecution execution, Variables variables) {
        String defaultInstantiatesCanonical = super.getInstantiatesCanonical(execution, variables);
        if (provider.subDic()) {
            Matcher matcher = INSTANTIATES_CANONICAL_PATTERN.matcher(defaultInstantiatesCanonical);
            if (matcher.matches()) {
                String match = matcher.group("processName");
                defaultInstantiatesCanonical = defaultInstantiatesCanonical
                        .replaceAll(match, "feasibilityExecute");
            }
        }
        return defaultInstantiatesCanonical;
    }

//    @Override
//    protected v
}