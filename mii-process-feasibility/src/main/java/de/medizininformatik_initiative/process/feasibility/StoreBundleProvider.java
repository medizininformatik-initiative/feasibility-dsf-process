package de.medizininformatik_initiative.process.feasibility;

import org.hl7.fhir.r4.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hl7.fhir.r4.model.Bundle.BundleType.TRANSACTION;

public interface StoreBundleProvider {
    Logger logger = LoggerFactory.getLogger(StoreBundleProvider.class);
    Pattern MEASURE_URL_PATTERN = Pattern.compile("(.+)/Measure/(.+)");
    Pattern LIBRARY_URL_PATTERN = Pattern.compile("urn:uuid:(.+)");
    String URL_UUID_PREFIX = "urn:uuid:";

    Bundle storeBundle(Bundle bundle);


    default Bundle storeTransactionBundle(MetadataResource... metadataResources) {
        Bundle bundle = new Bundle().setType(TRANSACTION);
        for (MetadataResource mr : metadataResources) {
            logger.info("Store `{}` `{}` `{}`", mr.getResourceType().name(), mr.getId(), mr.getUrl());
            bundle.addEntry().setResource(mr).getRequest()
                    .setMethod(Bundle.HTTPVerb.POST)
                    .setUrl(mr.getResourceType().name());
        }
        return storeBundle(bundle);
    }

    default void fixCanonical(Measure measure, Library library) {
        var measureUrlMatcher = MEASURE_URL_PATTERN.matcher(measure.getUrl());
        var libraryUrlMatcher = LIBRARY_URL_PATTERN.matcher(library.getUrl());
        if (measureUrlMatcher.find() && libraryUrlMatcher.find()) {
            var base = measureUrlMatcher.group(1);
            var measureId = measureUrlMatcher.group(2);
            var libraryId = libraryUrlMatcher.group(1);
            var libraryUrl = base + "/Library/" + libraryId;
            measure.setLibrary(new java.util.ArrayList<>());
            measure.addLibrary(libraryUrl);
            measure.setName(measureId);
            library.setUrl(libraryUrl);
            library.setName(libraryId);
            library.setVersion("1.0.0");
            if (library.getContent() != null && !library.getContent().isEmpty()) {
                var data = new String(library.getContent().get(0).getData(), UTF_8);
                var rest = data.split("\n", 2)[1];
                var newData = "library \"%s\" version '1.0.0'\n".formatted(libraryId) + rest;
                library.getContent().get(0).setData(newData.getBytes(UTF_8));
            }
        }
    }

    default String findIdPartInFirstBundleResourceType(Bundle transactionResponse, ResourceType resourceType) {
        try {
            return transactionResponse.getEntry().stream()
                    .filter(e -> e.getResource().getResourceType() == resourceType)
                    .findFirst().filter(bundleEntryComponent ->
                            bundleEntryComponent.getResource() != null &&
                                    bundleEntryComponent.getResource().getIdElement() != null)
                    .map(bundleEntryComponent -> bundleEntryComponent.getResource().getIdElement().getIdPart())
                    .orElse(null);
        } catch (Exception e) {
            logger.error("General Exception: " + e.getMessage(), e);
            e.printStackTrace();
        }
        return null;
    }
}

