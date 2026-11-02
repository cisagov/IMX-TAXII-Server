/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;

public class DataUtils {

	public static <T extends Comparable<T>> List<T> tidy(Collection<T> ts) {
		return tidy(ts, (t0, t1) -> t0.compareTo(t1));
	}

	public static <T> List<T> tidy(Collection<T> ts, Comparator<T> c) {
		if ((ts == null) || ts.isEmpty()) {
			return null;
		}
		List<T> tidy = new ArrayList<>(new HashSet<>(ts));
		Collections.sort(tidy, c);
		return tidy;
	}

	public static <T extends Comparable<T>> List<T> finalTidy(Collection<T> ts) {
		return finalTidy(ts, (t0, t1) -> t0.compareTo(t1));
	}

	public static <T> List<T> finalTidy(Collection<T> ts, Comparator<T> c) {
		List<T> tidy = tidy(ts, c);
		if (tidy != null) {
			tidy = Collections.unmodifiableList(tidy);
		}
		return tidy;
	}

}
