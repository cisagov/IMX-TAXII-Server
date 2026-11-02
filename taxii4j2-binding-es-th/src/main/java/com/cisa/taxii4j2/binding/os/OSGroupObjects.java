/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.os;

import java.security.Principal;
import java.util.List;
import java.util.Set;

import org.opensearch.client.opensearch._types.FieldValue;
import org.opensearch.client.opensearch._types.query_dsl.BoolQuery;
import org.opensearch.client.opensearch._types.query_dsl.Query;

import com.cisa.taxii4j2.auth.method.GroupAdmin;
import com.cisa.taxii4j2.binding.os.OSObjects;
import com.cisa.taxii4j2.method.impl.Nexts;
import com.cisa.taxii4j2.servlet.security.UserGroupPrincipal;
import com.cisa.taxii4j2.servlet.store.DbTaxii;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.SecurityContext;

@Singleton
public class OSGroupObjects extends OSObjects {

	@Context
	SecurityContext context;

	private final GroupAdmin groupAdmin;

	@Inject
	public OSGroupObjects(DbTaxii dbTaxii, Nexts nexts, GroupAdmin groupAdmin) {
		super(dbTaxii, nexts);
		this.groupAdmin = groupAdmin;
	}

	@Override
	protected Query groupQuery(Query query) {
		Principal principal = context.getUserPrincipal();
		if (principal == null) {
			return query;
		} else if (principal instanceof UserGroupPrincipal) {
			UserGroupPrincipal userGroupPrincipal = UserGroupPrincipal.class.cast(principal);
			Set<String> markings = groupAdmin.getMarkingsForUser(userGroupPrincipal.getName());
			markings.addAll(groupAdmin.getAllMarkings(userGroupPrincipal.groups()));
			if (markings.isEmpty()) {
				return query;
			} else {
				List<FieldValue> fieldValues = markings.stream().map(FieldValue::of).toList();
				Query noMarkingDefField = new BoolQuery.Builder().mustNot(o -> o.exists(f -> f.field("object_marking_refs"))).build().toQuery();
				Query markingRef = new BoolQuery.Builder().must(o -> o.terms(f -> f.field("object_marking_refs.keyword").terms(tf -> tf.value(fieldValues)))).build().toQuery();
				return new BoolQuery.Builder().must(query).must(o -> o.bool(f -> f.should(markingRef, noMarkingDefField))).build().toQuery();
			}
		} else {
			return query;
		}
	}

}
