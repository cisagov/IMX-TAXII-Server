/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.nio.file.FileSystemAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.Level;

import com.fasterxml.jackson.databind.JsonNode;
import com.networknt.schema.JsonMetaSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.SpecVersionDetector;
import com.networknt.schema.ValidationMessage;
import com.cisa.cti4j2.CommonProperty;
import com.cisa.cti4j2.JSON;
import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Type;
import com.cisa.taxii4j2.auth.data.Lenient;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.method.STIXValidator;
import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.method.TAXII.Validator;
import com.cisa.taxii4j2.method.TAXIIValidate;

public class TAXIIImplValidate implements TAXIIValidate {

	private static final String schemaDirName = "predefined-extension-schema";
	private static Map<String, JsonNode> predefined;

	@SafeVarargs
	public static TAXII compose(TAXII taxiiSlim, STIXValidator validator,
			Function<String, JsonNode>... schemaProviders) {

		try {
			final URI uri = ClassLoader.getSystemResource(schemaDirName).toURI();
			if (!uri.getScheme().equals("file")) {
				try {
					FileSystems.newFileSystem(uri, Map.of("create", "true"));
				} catch (FileSystemAlreadyExistsException e) {
					// NOP - no worries
					logger.log(Level.INFO, e.getMessage());
				}
			}
			predefined = new HashMap<>();
			Files.list(Paths.get(uri)).forEach(p -> {
				try (Reader in = Files.newBufferedReader(p)) {
					String key = p.getFileName().toString();
					int index = key.lastIndexOf(".json");
					if (index >= 0) {
						key = key.substring(0, index);
					}
					predefined.put(key, JSON.readTree(in));
				} catch (IOException e) {
					// NOP -better not happen...
					logger.log(Level.WARN, e.getMessage());
				}
			});
		} catch (Exception e) {
			// NOP - can't happen
			logger.log(Level.FATAL, e.getMessage());
		}

		/*
		 * MITRE validation
		 */
		taxiiSlim.addValidator(new Validator() {

			private STIXValidator.Result result;

			@Override
			public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients) {
				List<String> messages = new ArrayList<>();
				result = validator.validate(storable, STIXValidator.optionsFactory(lenients));
				String objType = storable.getStixType();
				for (STIXValidator.Error error : result.errors) {
					switch(objType) {
						case "artifact":
							if (!error.message.contains("mime_type")) {
								messages.add(error.message);
							}
							break;
						case "indicator":
							if (error.message.contains("hashes.TLSH")) {
								Pattern pattern = Pattern.compile("[\'\"](T.)?[a-zA-Z0-9]{70}[\'\"]");
								if (!pattern.matcher(error.message).find()) {
									messages.add(error.message);
								}
							}
							break;
						default:
							messages.add(error.message);
					}
				}
				return messages;
			}

			@Override
			public boolean getCheck(Set<Lenient> lenients) {
				return Action.DONT_MITRE_VALIDATE.test(lenients);
			}

			@Override
			public boolean getFail(Set<Lenient> lenients) {
				return Action.DONT_FAIL_MITRE_INVALID.test(lenients) && !result.is_valid;
			}

		});

		@SuppressWarnings("unused")
		final Validator internal = new Validator() {

			@Override
			public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients) {

				JsonNode extensions = storable.asObjectNode().get(CommonProperty.EXTENSIONS.getJsonKey());
				if (extensions == null) {
					return Collections.emptyList();
				}

				List<String> messages = new ArrayList<>();

				Iterator<Map.Entry<String, JsonNode>> iField = extensions.fields();
				while (iField.hasNext()) {

					Map.Entry<String, JsonNode> field = iField.next();
					String id = field.getKey();
					try {
						if (STIXIdentifier.getType(id) != Type.EXTENSION_DEFINITION) {
							continue;
						}
					} catch (Exception e) {
						if (!predefined.containsKey(id)) {
							messages.add(String.format("%s neither known predefined nor custom...", id));
						}
						continue;
					}

					JsonNode schema = null;
					for (Function<String, JsonNode> schemaProvider : schemaProviders) {
						try {
							schema = schemaProvider.apply(id);
							if (schema != null) {
								break;
							}
						} catch (Exception e) {

						}
					}
					if (schema == null) {
						messages.add(String.format("%s: couldn't find schema...", id));
						continue;
					}

					SpecVersion.VersionFlag version = SpecVersionDetector.detect(schema);
					JsonSchemaFactory.Builder builder = JsonSchemaFactory
							.builder(JsonSchemaFactory.getInstance(version));
					if (version != SpecVersion.VersionFlag.V202012) {
						builder.addMetaSchema(JsonMetaSchema.getV202012());
					}
					Set<ValidationMessage> vms = builder.build().getSchema(schema).validate(storable.asObjectNode());
					vms.forEach(vm -> messages.add(vm.getMessage()));

				}

				return messages;

			}

			@Override
			public boolean getCheck(Set<Lenient> lenients) {
				return Action.DONT_EXTENSION_VALIDATE.test(lenients);
			}

			@Override
			public boolean getFail(Set<Lenient> lenients) {
				return Action.DONT_FAIL_EXTENSION_INVALID.test(lenients);
			}

		};

		/*
		 * Custom extension schema validation
		 */
//		taxiiSlim.addValidator(internal);

		return taxiiSlim;

	}

}
