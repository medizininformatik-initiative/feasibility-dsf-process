package de.medizininformatik_initiative.process.feasibility.service;

import de.medizininformatik_initiative.process.feasibility.MeasureReportGenerator;
import de.medizininformatik_initiative.process.feasibility.Obfuscator;
import dev.dsf.bpe.v1.ProcessPluginApi;
import dev.dsf.bpe.v1.activity.AbstractServiceDelegate;
import dev.dsf.bpe.v1.variables.Variables;
import org.camunda.bpm.engine.delegate.DelegateExecution;
import org.hl7.fhir.r4.model.CodeableConcept;
import org.hl7.fhir.r4.model.Coding;
import org.hl7.fhir.r4.model.MeasureReport;
import org.hl7.fhir.r4.model.Period;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import java.util.Objects;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_MEASURE_POPULATION;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.MEASURE_REPORT_PERIOD_END;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.MEASURE_REPORT_PERIOD_START;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.VARIABLE_MEASURE_REPORT;
import static java.lang.String.format;
import static org.hl7.fhir.r4.model.MeasureReport.MeasureReportStatus.COMPLETE;
import static org.hl7.fhir.r4.model.MeasureReport.MeasureReportType.SUMMARY;

public class ObfuscateEvaluationResult extends AbstractServiceDelegate
        implements InitializingBean, MeasureReportGenerator {
    private static final Logger logger = LoggerFactory.getLogger(ObfuscateEvaluationResult.class);

    private final Obfuscator<Integer> obfuscator;

    public ObfuscateEvaluationResult(Obfuscator<Integer> obfuscator, ProcessPluginApi api) {
        super(api);
        this.obfuscator = obfuscator;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        super.afterPropertiesSet();
        Objects.requireNonNull(obfuscator, "obfuscator");
    }

    @Override
    protected void doExecute(DelegateExecution execution, Variables variables) {
        logger.info("doExecute obfuscate evaluation result");

        var measureReport = (MeasureReport) variables.getResource(VARIABLE_MEASURE_REPORT);

        if (measureReport.getStatus() == COMPLETE) {
            variables.setResource(VARIABLE_MEASURE_REPORT, obfuscateFeasibilityCount(measureReport));
        } else {
            throw new RuntimeException(format("Expected status '%s' but actually is '%s' for measure report (id '%s').",
                    COMPLETE, measureReport.getStatus(), measureReport.getId()));
        }
    }

    private MeasureReport obfuscateFeasibilityCount(MeasureReport measureReport) {
        var obfuscatedFeasibilityCount = obfuscator.obfuscate(extractInitialPopulation(measureReport).getCount());

        var obfuscatedMeasureReport = new MeasureReport()
                .setStatus(COMPLETE)
                .setType(SUMMARY)
                .setMeasure(measureReport.getMeasure())
                .setPeriod(new Period()
                        .setStart(MEASURE_REPORT_PERIOD_START)
                        .setEnd(MEASURE_REPORT_PERIOD_END));

        obfuscatedMeasureReport.getGroupFirstRep().getPopulationFirstRep()
                .setCode(new CodeableConcept().addCoding(new Coding().setSystem(CODESYSTEM_MEASURE_POPULATION)
                        .setCode(CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION)))
                .setCount(obfuscatedFeasibilityCount);

        return obfuscatedMeasureReport;
    }

}
