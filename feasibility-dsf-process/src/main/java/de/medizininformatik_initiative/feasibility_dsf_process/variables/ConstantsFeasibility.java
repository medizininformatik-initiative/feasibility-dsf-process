package de.medizininformatik_initiative.feasibility_dsf_process.variables;

public interface ConstantsFeasibility {
    String VARIABLE_MEASURE = "measure";
    String VARIABLE_LIBRARY = "library";
    String VARIABLE_MEASURE_ID = "measure-id";
    String VARIABLE_MEASURE_REPORT = "measure-report";
    String VARIABLE_MEASURE_REPORT_ID = "measure-report-id";
    String VARIABLE_MEASURE_REPORT_MAP = "measure-report-map";
    String VARIABLE_EVALUATION_STRATEGY = "evaluation-strategy";
    String VARIABLE_EVALUATION_OBFUSCATION = "evaluation-obfuscation";
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
}
