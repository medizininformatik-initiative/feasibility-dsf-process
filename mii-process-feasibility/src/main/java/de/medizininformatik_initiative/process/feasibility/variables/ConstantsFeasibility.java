package de.medizininformatik_initiative.process.feasibility.variables;

import org.hl7.fhir.r4.model.Coding;
import org.joda.time.LocalDate;

import java.time.Duration;
import java.util.Date;

public interface ConstantsFeasibility {
    String VARIABLE_MEASURE = "measure";
    String VARIABLE_LIBRARY = "library";
    String VARIABLE_MEASURE_ID = "measure-id";
    String VARIABLE_MEASURE_REPORT = "measure-report";
    String VARIABLE_MEASURE_REPORT_ID = "measure-report-id";
    String VARIABLE_MEASURE_REPORT_MAP = "measure-report-map";
    String VARIABLE_EVALUATION_STRATEGY = "evaluation-strategy";
    String VARIABLE_EVALUATION_OBFUSCATION = "evaluation-obfuscation";
    String VARIABLE_REQUEST_RATE_BELOW_LIMIT = "request-rate-below-limit";
    String VARIABLE_REQUESTER_PARENT_ORGANIZATION = "requester-parent-organization";

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
    String MEASURE_REPORT_TYPE_POPULATION = "population";

    int CLIENT_TIMEOUT_DEFAULT = 300000;
    String SETTINGS_NETWORK_ALL = "all";
    int DEFAULT_RATE_LIMIT_COUNT = 999;
    Duration DEFAULT_RATE_LIMIT_DURATION = Duration.ofHours(1);
    String VARIABLE_MEASURE_RESULT_CQL = "measure-result-cql";
    String VARIABLE_MEASURE_RESULT_CCDL = "measure-result-ccdl";

    public double DEFAULT_OBFUSCATION_LAPLACE_SENSITIVITY = 1.0d;
    public double DEFAULT_OBFUSCATION_LAPLACE_EPSILON = 0.5d;
    public String CODESYSTEM_ORGANIZATION_ROLE = "http://dsf.dev/fhir/CodeSystem/organization-role";
    Coding DIC = new Coding(CODESYSTEM_ORGANIZATION_ROLE, "DIC", "Data Integration Center");
    Coding HRP = new Coding(CODESYSTEM_ORGANIZATION_ROLE, "HRP", "Health Research Portal");
}
