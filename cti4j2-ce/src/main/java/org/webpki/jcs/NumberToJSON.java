/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package org.webpki.jcs;

import java.io.IOException;

/**
 * JSON as specified by ECMAScript
 */
public final class NumberToJSON {
    /**
     * Formats a number according to ECMAScript.
     * <p>
     * This code is emulating 7.1.12.1 of the EcmaScript V6 specification.
     * </p>
     *
     * @param value Value to be formatted
     * @return String representation
     */
    public static String serializeNumber(double value) throws IOException {
        // First, handle the JSON cases.
        if (value == 0.0) {
            return "0";
        }
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            throw new IOException("NaN/Infinity not allowed in JSON");
        }
        return DoubleCoreSerializer.serialize(value, true);
    }
}
