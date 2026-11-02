/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.misp;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Iterator;
import java.util.Set;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonMetaSchema;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.SpecVersionDetector;
import com.networknt.schema.ValidationMessage;
import com.cisa.cti4j2.JSON;

public class ValidateTest {

	@Test
	public void test() {

		JsonNode object = null;
		try(InputStream in = ClassLoader.getSystemResourceAsStream("last1d.json")) {
			object = JSON.readTree(new InputStreamReader(in));
		} catch (IOException e) {
			fail(e.getMessage());
		}

		event("schema.json", object);
		event("schema-lax.json", object);

	}

	private void event(String path, JsonNode object) {

		System.out.println(String.format("\n%s\n", path));

		JsonNode schema = null;
		try(InputStream in = ClassLoader.getSystemResourceAsStream(path)) {
			schema = JSON.readTree(new InputStreamReader(in));
		} catch (IOException e) {
			fail(e.getMessage());
		}

		SpecVersion.VersionFlag version = SpecVersionDetector.detect(schema);
		JsonSchemaFactory.Builder builder = JsonSchemaFactory
				.builder(JsonSchemaFactory.getInstance(version));
		if (version != SpecVersion.VersionFlag.V202012) {
			builder.addMetaSchema(JsonMetaSchema.getV202012());
		}
		JsonSchema validator = builder.build().getSchema(schema);

		Iterator<JsonNode> iEvent = object.get("response").elements();
		while(iEvent.hasNext()) {
			Set<ValidationMessage> vms = validator.validate(iEvent.next());
			vms.forEach(vm -> System.out.println(vm));
			System.out.println();
		}

	}

}
