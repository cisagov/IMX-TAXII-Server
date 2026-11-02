/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method;

import java.util.Set;

import com.cisa.taxii4j2.auth.data.Lenient;

public interface TAXIIBestPractices {

	public enum Action implements Lenient {

		DONT_CHECK_CUSTOM_OBJECTS, DONT_FAIL_CUSTOM_OBJECTS, //
		DONT_CHECK_CUSTOM_PROPERTIES, DONT_FAIL_CUSTOM_PROPERTIES, //
//		REMOVE_EMPTY_ARRAYS(true), DONT_FAIL_EMPTY_ARRAYS, //
		DONT_REMOVE_EMPTY_ARRAYS, FAIL_EMPTY_ARRAYS(true), //
//		TRIM_URLS(true), DONT_FAIL_URLS, //
		DONT_TRIM_URLS, FAIL_TRIMMED_URLS(true), //
		DONT_CHECK_SCO_IDS, FAIL_SCO_IDS(true), //
		DONT_CHECK_NA_COMMONS, DONT_FAIL_NA_COMMONS; //

		private final boolean lenient;

		private Action() {
			this(false);
		}

		private Action(boolean lenient) {
			this.lenient = lenient;

		}

		@Override
		public boolean test(Set<Lenient> lenients) {
			return lenient ^ ((lenients == null) || !lenients.contains(this));
		}

	}

}
