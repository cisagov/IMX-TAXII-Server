/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.cisa.cti4j2.STIXIdentifier;
import com.cisa.cti4j2.Type;
import com.cisa.taxii4j2.auth.data.Lenient;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.method.TAXII.Validator;
import com.cisa.taxii4j2.method.TAXIIBestPractices;

public class TAXIIImplBP implements TAXIIBestPractices {

	public static TAXII compose(TAXII taxiiSlim) {

		/*
		 * custom objects
		 */
//		taxiiSlim.addValidator(new Validator() {
//
//			@Override
//			public List<String> validate(STIXObject storable, String cId) {
//				return storable.isCustom();
//			}
//
//			@Override
//			public Lenient getCheck() {
//				return Action.DONT_CHECK_CUSTOM_OBJECTS;
//			}
//
//			@Override
//			public Lenient getFail() {
//				return Action.DONT_FAIL_CUSTOM_OBJECTS;
//			}
//
//		});

		/*
		 * custom properties
		 */
//		taxiiSlim.addValidator(new Validator() {
//
//			@Override
//			public List<String> validate(STIXObject storable, String cId) {
//				return storable.removeCustomProperties();
//			}
//
//			@Override
//			public Lenient getCheck() {
//				return Action.DONT_CHECK_CUSTOM_PROPERTIES;
//			}
//
//			@Override
//			public Lenient getFail() {
//				return Action.DONT_FAIL_CUSTOM_PROPERTIES;
//			}
//		});

		/*
		 * empty arrays
		 */
		taxiiSlim.addValidator(new Validator() {

			@Override
			public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients) {
				return storable.removeEmptyArrays();
			}

			@Override
			public boolean getCheck(Set<Lenient> lenients) {
//				return Action.REMOVE_EMPTY_ARRAYS;
				return Action.DONT_REMOVE_EMPTY_ARRAYS.test(lenients);
			}

			@Override
			public boolean getFail(Set<Lenient> lenients) {
//				return Action.DONT_FAIL_EMPTY_ARRAYS;
				return Action.FAIL_EMPTY_ARRAYS.test(lenients);
			}

		});

		/*
		 * padded text fields (not really URLs, but targeted at that problem...)
		 */
		taxiiSlim.addValidator(new Validator() {

			@Override
			public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients) {
				return storable.trimTexts();
			}

			@Override
			public boolean getCheck(Set<Lenient> lenients) {
//				return Action.TRIM_URLS;
				return Action.DONT_TRIM_URLS.test(lenients);
			}

			@Override
			public boolean getFail(Set<Lenient> lenients) {
//				return Action.DONT_FAIL_URLS;
				return Action.FAIL_TRIMMED_URLS.test(lenients);
			}

		});

		/*
		 * not applicable common attributes
		 */
		taxiiSlim.addValidator(new Validator() {

			@Override
			public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients) {
				return storable.checkHasNa();
			}

			@Override
			public boolean getCheck(Set<Lenient> lenients) {
				return Action.DONT_CHECK_NA_COMMONS.test(lenients);
			}

			@Override
			public boolean getFail(Set<Lenient> lenients) {
				return Action.DONT_FAIL_NA_COMMONS.test(lenients);
			}

		});

		/*
		 * SCO ids
		 */
		taxiiSlim.addValidator(new Validator() {

			@Override
			public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients) {
				try {
					Type type = storable.getType();
					if (type.isSCO() && (type != Type.PROCESS)) {
						UUID given = STIXIdentifier.getUuid(storable.getId());
						UUID computed = type.getUuid(storable.asObjectNode());
						if (given.compareTo(computed) != 0) {
							return Collections.singletonList(String.format("id UUID %s should be %s", given, computed));
						}
					}
				} catch (Exception e) {

				}
				return Collections.emptyList();
			}

			@Override
			public boolean getCheck(Set<Lenient> lenients) {
				return Action.DONT_CHECK_SCO_IDS.test(lenients);
			}

			@Override
			public boolean getFail(Set<Lenient> lenients) {
				return Action.FAIL_SCO_IDS.test(lenients);
			}

		});

		return taxiiSlim;

	}

}
