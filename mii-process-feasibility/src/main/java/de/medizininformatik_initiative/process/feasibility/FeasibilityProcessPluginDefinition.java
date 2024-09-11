package de.medizininformatik_initiative.process.feasibility;

import com.google.common.base.Strings;
import de.medizininformatik_initiative.process.feasibility.client.flare.FlareWebserviceClientSpringConfig;
import de.medizininformatik_initiative.process.feasibility.client.store.StoreClientSpringConfig;
import de.medizininformatik_initiative.process.feasibility.service.SelectRequestTargets;
import de.medizininformatik_initiative.process.feasibility.spring.config.BaseConfig;
import de.medizininformatik_initiative.process.feasibility.spring.config.EnhancedFhirWebserviceClientProviderConfig;
import de.medizininformatik_initiative.process.feasibility.spring.config.EvaluationConfig;
import de.medizininformatik_initiative.process.feasibility.spring.config.FeasibilityConfig;
import dev.dsf.bpe.v1.ProcessPluginDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static com.google.common.base.Preconditions.checkNotNull;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.FEASIBILITY_EXECUTE_PROCESS_ID;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.FEASIBILITY_REQUEST_PROCESS_ID;

public class FeasibilityProcessPluginDefinition implements ProcessPluginDefinition {


    private static final Logger logger = LoggerFactory.getLogger(SelectRequestTargets.class);

    public final String version;
    private final LocalDate releaseDate;
    public FeasibilityProcessPluginDefinition() {
        try (var input = FeasibilityProcessPluginDefinition.class.getClassLoader()
                .getResourceAsStream("app.properties")) {
            checkNotNull(input);
            var props = new Properties();
            props.load(input);
            this.version = props.getProperty("build.version").replaceFirst("-.*$", "");
            this.releaseDate = LocalDate.parse(props.getProperty("build.date"));
        } catch (IOException e) {
            throw new IllegalStateException("Could not load application properties.", e);
        }
    }

    @Override
    public String getName() {
        return "mii-process-feasibility";
    }

    @Override
    public String getVersion() {
        return version;
    }

    @Override
    public LocalDate getReleaseDate() {
        return releaseDate;
    }

    @Override
    public List<String> getProcessModels() {
        return List.of("bpe/feasibilityRequest.bpmn", "bpe/feasibilityExecute.bpmn");
    }

    @Override
    public List<Class<?>> getSpringConfigurations() {
        return List.of(BaseConfig.class, StoreClientSpringConfig.class, FeasibilityConfig.class,
                EnhancedFhirWebserviceClientProviderConfig.class, EvaluationConfig.class,
                FlareWebserviceClientSpringConfig.class);
    }

    @Override
    public Map<String, List<String>> getFhirResourcesByProcessId() {

        var aExe = "fhir/ActivityDefinition/feasibilityExecute.xml";
        var aReq = "fhir/ActivityDefinition/feasibilityRequest.xml";

        var cF = "fhir/CodeSystem/feasibility.xml";

        var sExtDic = "fhir/StructureDefinition/feasibility-extension-dic.xml";

        var sMeasure = "fhir/StructureDefinition/feasibility-measure.xml";
        var sMeasureReport = "fhir/StructureDefinition/feasibility-measure-report.xml";
        var sLibrary = "fhir/StructureDefinition/feasibility-library.xml";

        var sTExe = "fhir/StructureDefinition/feasibility-task-execute.xml";
        var sTReq = "fhir/StructureDefinition/feasibility-task-request.xml";
        var sTResS = "fhir/StructureDefinition/feasibility-task-single-dic-result.xml";

        var vF = "fhir/ValueSet/feasibility.xml";

        return Map.of(
                FEASIBILITY_EXECUTE_PROCESS_ID,
                Arrays.asList(aExe, sTExe, sTResS, vF, cF, sMeasure, sMeasureReport, sLibrary),
                FEASIBILITY_REQUEST_PROCESS_ID,
                Arrays.asList(aReq, sTReq, sTResS, sExtDic, vF, cF, sMeasure, sMeasureReport, sLibrary)
        );
    }
}
