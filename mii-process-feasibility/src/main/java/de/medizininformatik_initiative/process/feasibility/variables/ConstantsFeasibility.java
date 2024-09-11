package de.medizininformatik_initiative.process.feasibility.variables;

import org.joda.time.LocalDate;

import java.util.Date;

public interface ConstantsFeasibility {
    String VARIABLE_MEASURE = "measure";
    String VARIABLE_LIBRARY = "library";
    String VARIABLE_DISTRIBUTION_MEASURE_ID = "measure-distribution-id";
    String VARIABLE_DISTRIBUTION_LIBRARY_ID = "library-distribution-id";
    String VARIABLE_MEASURE_ID = "measure-id";
    String VARIABLE_MEASURE_REPORT = "measure-report";
    String VARIABLE_MEASURE_REPORT_ID = "measure-report-id";
    String VARIABLE_MEASURE_REPORT_MAP = "measure-report-map";
    String VARIABLE_EVALUATION_STRATEGY = "evaluation-strategy";
    String VARIABLE_EVALUATION_OBFUSCATION = "evaluation-obfuscation";
    String VARIABLE_FEASIBILITY_DISTRIBUTION = "feasibility-distribution";
    String VARIABLE_EVALUATION_OBFUSCATION_LAPLACE_SENSITIVITY = "evaluation-obfuscation-laplace-sensitivity";
    String VARIABLE_EVALUATION_OBFUSCATION_LAPLACE_EPSILON = "evaluation-obfuscation-laplace-epsilon";
    String VARIABLE_REQUEST_RATE_BELOW_LIMIT = "request-rate-below-limit";

    String CODESYSTEM_FEASIBILITY = "http://medizininformatik-initiative.de/fhir/CodeSystem/feasibility";
    String CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REFERENCE = "measure-reference";
    String CODESYSTEM_FEASIBILITY_VALUE_MEASURE_REPORT_REFERENCE = "measure-report-reference";
    String CODESYSTEM_MEASURE_POPULATION = "http://terminology.hl7.org/CodeSystem/measure-population";
    String CODESYSTEM_MEASURE_POPULATION_VALUE_INITIAL_POPULATION = "initial-population";

    String EXTENSION_DIC_URI = "http://medizininformatik-initiative.de/fhir/StructureDefinition/dic";

    String FEASIBILITY_REQUEST_PROCESS_ID = "medizininformatik-initiativede_feasibilityRequest";
    String FEASIBILITY_EXECUTE_PROCESS_ID = "medizininformatik-initiativede_feasibilityExecute";
    Date MEASURE_REPORT_PERIOD_START = new LocalDate(1900, 1, 1).toDate();
    Date MEASURE_REPORT_PERIOD_END = new LocalDate(2100, 1, 1).toDate();

    int CLIENT_TIMEOUT_DEFAULT = 300000;
}
