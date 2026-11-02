/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.cisa.taxii4j2.auth.data.Lenient;

public interface TAXIIValidate {

	public static final Logger logger = LogManager.getLogger(TAXIIValidate.class);

	public enum Action implements Lenient {

		DONT_MITRE_VALIDATE, DONT_FAIL_MITRE_INVALID, //
		DONT_EXTENSION_VALIDATE, DONT_FAIL_EXTENSION_INVALID; //

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
