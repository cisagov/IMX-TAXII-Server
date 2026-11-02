/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;

import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

@JsonSerialize(using = Filters.Serializer.class)
@JsonDeserialize(using = Filters.Deserializer.class)
public class Filters implements Iterable<Map.Entry<String, Set<String>>> {

	private MultivaluedMap<String, String> qps;

	public MultivaluedMap<String, String> getQps() {
		return new MultivaluedHashMap<>(qps);
	}

	public static final String allKey = "all";
	public static final String idKey = "id";
	public static final String versionKey = "version";
	public static final String firstKey = "first";
	public static final String lastKey = "last";
	public static final String limitKey = "limit";
	public static final String nextKey = "next";
	public static final String added_afterKey = "added_after";
	public static final String spec_versionKey = "spec_version";
	public static final String typeKey = "type";

	/*
	 * Tier 0: fields required by the TAXII specification
	 * Tier 1: top level string fields
	 * Tier 2: top level array fields
	 * Tier 3: not top level fields, match field must map to a field in an embedded object
	 */
	public static Set<String> tier0 = Set.of("id", "spec_version", "type", "version");

	public static Set<String> tier1 = Set.of("account_type", "confidence", "context", "data_type", "dst_port",
			"encryption_algorithm", "identity_class", "name", "number", "opinion", "pattern", "pattern_type",
			"primary_motivation", "region", "relationship_type", "resource_level", "result", "revoked", "src_port",
			"sophistication", "subject", "value", "country", "administrative_area", "created_by_ref");

	public static Set<String> tier2 = Set.of("aliases", "architecture_executions_envs", "capabilities",
			"extension_types", "implementation_languages", "indicator_types", "infrastructure_types", "labels",
			"malware_types", "personal_motivations", "report_types", "roles", "secondary_motivations", "sectors",
			"threat_actor_types", "tool_types");

	private static Map<String, String> tier3_0 = Map.of(

			// easy
			"address_family", "extensions.socket-ext.address_family",

			/*
			 * The address family of the Network Socket object. Value type:
			 * network-socket-address-family-enum Examples
			 * ?match[address_family]=AF_APPLETALK ?match[address_family]=AF_INET,AF_INET6
			 */

			// easy
			"MD5", "hashes.MD5", "SHA-1", "hashes.SHA-1", "SHA-256", "hashes.SHA-256", "SHA-512", "hashes.SHA-512",
			"SHA3-256", "hashes.SHA3-256", "SHA3-512", "hashes.SHA3-512", "SSDEEP", "hashes.SSDEEP", "TLSH",
			"hashes.TLSH"

	/*
	 * The Hashing Algorithm open vocabulary (hash-algorithm-ov) is used in the
	 * External Reference, Artifact, File, Alternate Data Stream, Windows PE Binary
	 * File, Windows PE Optional Header, Windows PE Section, and X.509 Certificate
	 * objects, which each include a hashes property of type hashes (a set of
	 * key/value pairs). Value type: string Examples
	 * ?match[SHA-256]=35a01331e9ad96f751278b891b6ea09699806faedfa237d40513d
	 * 92ad1b7100f
	 * ?match[MD5]=9e04af713d91d493ef3301a050a18b7a,53d780fc1453f56d6dff77a93a920794
	 */
	);

	private static Map<String, String> tier3_1 = Map.of(

			// easy
			"integrity_level", "extensions.windows-process-ext.integrity_level",

			/*
			 * The integrity level of the Windows Process object. Value type:
			 * windows-integrity-level-enum Examples ?match[integrity_level]=high
			 * ?match[integrity_level]=medium,high
			 */

			// easy
			"pe_type", "extensions.windows-pebinary-ext.pe_type",

			/*
			 * The type of PE binary object. Value type: windows-pebinary-type-ov Examples
			 * ?match[pe_type]=dll ?match[pe_type]=dll,exe
			 */

			// easy
			"service_status", "extensions.windows-service-ext.service_status",

			/*
			 * The current status of the Windows Service object. Value type:
			 * windows-service-status-enum Examples ?match[service_status]=SERVICE_STOPPED
			 * ?match[service_status]=SERVICE_RUNNING,SERVICE_START_PENDING
			 */

			// easy
			"service_type", "extensions.windows-service-ext.service_type",

			/*
			 * The type of the Windows Service object. Value type: windows-service-type-enum
			 * Examples ?match[service_type]=SERVICE_WIN32_OWN_PROCESS
			 * ?match[service_type]=SERVICE_KERNEL_DRIVER,SERVICE_FILE_SYSTEM_DRIVER
			 */

			// easy
			"socket_type", "extensions.socket-ext.socket_type",

			/*
			 * The type of Network Socket object. Value type: network-socket-type-enum
			 * Examples ?match[socket_type]=SOCK_RAW
			 * ?match[socket_type]=SOCK_STREAM,SOCK_SEQPACKET
			 */

			// easy
			"start_type", "extensions.windows-service-ext.start_type",

			/*
			 * The start options of the Windows Service object. Value type:
			 * windows-service-start-type-enum Examples ?match[start_type]=SERVICE_DISABLED
			 * ?match[start_type]=SERVICE_AUTO_START,SERVICE_BOOT_START
			 */

			// easy
			"tlp", "definition.tlp"

	/*
	 * The marking-definition identifier applied to object(s). This is a shorthand
	 * to objects specifically marked with a TLP marking. The only allowed values
	 * MUST are white, green, amber, and red. Specific IDs for each TLP color MUST
	 * be mapped as defined on the TLP Marking Object Type section in [STIX™ Version
	 * 2.1]. Value type: string Examples ?match[tlp]=white ?match[tlp]=white,green
	 */

	);

	public static Map<String, String> tier3Array = Map.of(

			// external_references is an array, source_name a field in an element
			"source_name", "external_references.source_name",

			/*
			 * A source name present in any STIX object(s) external_references property.
			 * Value type: string Examples ?match[source_name]=cve
			 * ?match[source_name]=capec,veris
			 */

			// external_references is an array, external_id field in an element
			"external_id", "external_references.external_id",

			/*
			 * An identifier present in any STIX object(s) external_references property.
			 * Value type: string Examples ?match[external_id]=CVE-2016-1234
			 * ?match[external_id]=CWE-20,T1245
			 */

			// kill_chain_phases is an array, phase_name property of element
			"phase_name", "kill_chain_phases.phase_name"

	/*
	 * The name of the phase in a kill chain as defined in the kill_chain_phases
	 * property of an Attack Pattern, Indicator, Infrastructure, Malware, or Tool
	 * object. Value type: string Examples ?match[phase_name]=reconnaissance
	 * ?match[phase_name]=pre%2Dattack,post%2Dattack
	 */

	);

	public static Map<String, String> tier3;
	static {
		tier3 = new HashMap<>(tier3_0);
		tier3.putAll(tier3_1);
		tier3 = java.util.Collections.unmodifiableMap(tier3);
	}

	public static final String relationships_allKey = "relationships-all";

	public static final Set<String> refs = Set.of("analysis_sco_refs", "bcc_refs", "belongs_to_ref", "belongs_to_refs",
			"body_raw_ref", "cc_refs", "child_refs", "contains_refs", "content_ref", "created_by_ref",
			"creator_user_ref", "dst_payload_ref", "dst_ref", "encapsulated_by_ref", "encapsulates_refs", "from_ref",
			"host_vm_ref", "image_ref", "installed_software_refs", "marking_ref", "message_body_data_ref",
			"object_marking_refs", "object_ref", "object_refs", "observed_data_refs", "opened_connections_refs",
			"operating_system_ref", "operating_system_refs", "parent_directory_ref", "parent_ref", "raw_email_ref",
			"resolves_to_refs", "sample_ref", "sample_refs", "sender_ref", "service_dll_refs", "sighting_of_ref",
			"source_ref", "src_payload_ref", "src_ref", "target_ref", "to_refs", "where_sighted_refs");

	public static final Set<String> fields = Set.of("confidence", "modified", "number", "src_port", "dst_port",
			"valid_until", "valid_from");

	public static final Set<String> ops = Set.of("gte", "lte");

	public static String[] parts(String key) {
		String[] parts = key.split("-");
		return ((parts.length == 2) && fields.contains(parts[0]) && ops.contains(parts[1])) ? parts : null;
	}

	public static String field(String key) {
		String[] parts = parts(key);
		return (parts != null) ? parts[0] : null;
	}

	public static String op(String key) {
		String[] parts = parts(key);
		return (parts != null) ? parts[1] : null;
	}

	public static final String GTE = "gte";
	public static final String LTE = "lte";

	public static String match(String key) {
		return String.format("match[%s]", key);
	}

	private static final Matcher unmatcher = Pattern.compile("match\\[([^\\]]+)\\]").matcher("");

	public static String unmatch(String value) {
		synchronized (unmatcher) {
			unmatcher.reset(value);
			if (unmatcher.matches()) {
				return unmatcher.group(1);
			}
		}
		return null;
	}

	private Set<String> flatten(String key) {
		return flatten(qps, key);
	}

	public static Set<String> flatten(MultivaluedMap<String, String> qps, String key) {
		List<String> values = qps.get(key);
		return ((values != null) && !values.isEmpty()) ? values.stream().map(v -> Arrays.stream(v.split("\\s*,\\s*")))
				.flatMap(s -> s).collect(Collectors.toSet()) : null;
	}

	private String singleValue(String key) {
		return singleValue(qps, key);
	}

	public static String singleValue(MultivaluedMap<String, String> qps, String key) {
		Set<String> values = flatten(qps, key);
		if (values == null) {
			return null;
		}
		switch (values.size()) {
		case 0:
			return null;
		case 1:
			return values.iterator().next();
		default:
			throw new IllegalArgumentException();
		}
	}

	public Filters() {
		super();
		qps = new MultivaluedHashMap<>();
	}

	public static Filters create(String s) {
		MultivaluedMap<String, String> qps = new MultivaluedHashMap<>();
		for (String param : s.split("\\s*\\&\\s*")) {
			String[] kv = param.split("\\s*=\\s*", 2);
			if (kv.length == 2) {
				qps.computeIfAbsent(kv[0], k -> new ArrayList<>()).add(kv[1]);
			} else {
				LogManager.getLogger(Filters.class)
						.warn(String.format("Filters.create: couldn't parse \"%s\" from \"%s\"", param, s));
			}
		}
		return qps.isEmpty() ? new Filters() : new Filters(qps);
	}

	private static final Set<String> matchless = Set.of(added_afterKey, nextKey, limitKey);
	private static Set<String> computed = fields.stream()
			.map(field -> ops.stream().map(op -> String.format("%s-%s", field, op))).flatMap(s -> s)
			.collect(Collectors.toSet());

	public Filters(MultivaluedMap<String, String> queryParameters) {
		super();
		qps = new MultivaluedHashMap<>(queryParameters);
		validate();
	}

	public Filters(String qps) {

		super();

		this.qps = new MultivaluedHashMap<>();

		if ((qps == null) || qps.isBlank()) {
			return;
		}

		for (String kv : qps.split("&")) {
			String[] parts = kv.split("=");
			this.qps.add(parts[0], URLDecoder.decode(parts[1], Charset.defaultCharset()));
		}

		validate();

	}

	private void validate() {

		MultivaluedMap<String, String> queryParameters = new MultivaluedHashMap<>(qps);

		if (queryParameters.values().stream().anyMatch(v -> v.size() > 1)) {
			throw new IllegalArgumentException("one or more filter parameters appear more than once...");
		}

		Set<String> keys = new HashSet<>(queryParameters.keySet());
		keys.removeAll(matchless);
		Set<String> unknown = keys.stream().filter(k -> unmatch(k) == null).collect(Collectors.toSet());
		if (!unknown.isEmpty()) {
			throw new IllegalArgumentException(String.format("unknown filter(s): %s", unknown));
		}

		Set<String> matches = keys.stream().map(k -> unmatch(k)).collect(Collectors.toSet());
		matches.removeAll(tier0);
		matches.removeAll(tier1);
		matches.removeAll(tier2);
		matches.removeAll(tier3.keySet());
		matches.removeAll(tier3Array.keySet());
		matches.remove(relationships_allKey);
		matches.removeAll(computed);
		if (!matches.isEmpty()) {
			throw new IllegalArgumentException(String.format("unknown match filter(s): %s", matches));
		}

	}

	public Filters(Filters src) {
		/*
		 * bypasses validation...
		 */
		super();
		qps = new MultivaluedHashMap<>(src.qps);
	}

	public Set<String> getId() {
		return flatten(match(idKey));
	}

	public Filters set(boolean clear, String key, String... value) {
		return set(clear, key, new HashSet<>(Arrays.asList(value)));
	}

	public Filters set(boolean clear, String key, Set<String> curr) {
		Set<String> prev = clear ? null : flatten(key);
		if (prev == null) {
			prev = curr;
		} else {
			prev.addAll(curr);
		}
		qps.put(key, new ArrayList<>(prev));
		return this;
	}

	public Filters setId(boolean clear, String... oId) {
		return set(clear, match(idKey), oId);
	}

	private boolean is(String value) {
		Set<String> version = flatten(match(versionKey));
		return (version != null) ? version.contains(value) : false;
	}

	public boolean isAll() {
		return is(allKey);
	}

	public boolean isFirst() {
		return is(firstKey);
	}

	public boolean isLast() {
		Set<String> version = flatten(match(versionKey));
		if (version == null) {
			return true;
		}
		version.retainAll(Set.of(allKey, firstKey, lastKey));
		return version.isEmpty() ? true : version.contains(lastKey);
	}

	public Set<String> getVersion() {
		Set<String> version = flatten(match(versionKey));
		if (version == null) {
			return version;
		}
		version.removeAll(Set.of(allKey, firstKey, lastKey));
		return version.isEmpty() ? null : version;
	}

	public Filters setVersion(boolean clear, String... version) {
		return set(clear, match(versionKey), version);
	}

	public Filters setType(boolean clear, String... type) {
		return set(clear, match(typeKey), type);
	}

	public Filters setLimit(Integer limit) {
		if (limit < 0) {
			throw new IllegalArgumentException("Filters.setLimit");
		}
		return set(true, limitKey, limit.toString());
	}

	public Integer getLimit() {
		String value = singleValue(limitKey);
		int limitMax = TAXIIConfig.limitMax();
		Integer limit = (value != null) ? Math.min(Integer.valueOf(value), limitMax) : limitMax;
		if (limit <= 0) {
			throw new IllegalArgumentException("Filters.getLimit");
		}
		return limit;
	}

	public Timestamp getAdded_after() {
		try {
			return Timestamp.valueOf(singleValue(added_afterKey));
		} catch (Exception e) {
			return Timestamp.epoch;
		}
	}

	public Filters setAdded_after(Timestamp date_added) {
		qps.put(added_afterKey, java.util.Collections.singletonList(date_added.toString()));
		return this;
	}

	public String getNext() {
		return singleValue(nextKey);
	}

	public WebTarget addQueryParams(WebTarget target) {
		for (Map.Entry<String, List<String>> qp : qps.entrySet()) {
			target = target.queryParam(qp.getKey(), String.join(",", qp.getValue()));
		}
		return target;
	}

	public Set<String> getSpec_version() {
		return flatten(match(spec_versionKey));
	}

	public Set<String> getType() {
		return flatten(match(typeKey));
	}

	public static class Serializer extends StdSerializer<Filters> {

		private static final long serialVersionUID = 1L;

		public Serializer() {
			super(Filters.class);
		}

		@Override
		public void serialize(Filters value, JsonGenerator gen, SerializerProvider provider) throws IOException {
			gen.writeObject(value.qps);
		}
	}

	public static class Deserializer extends StdDeserializer<Filters> {

		private static final long serialVersionUID = 1L;

		public Deserializer() {
			super(Filters.class);
		}

		@SuppressWarnings("unchecked")
		@Override
		public Filters deserialize(JsonParser p, DeserializationContext ctxt)
				throws IOException, JsonProcessingException {
			return new Filters(p.readValueAs(MultivaluedHashMap.class));
		}
	}

	public String get(String key) {
		return singleValue(match(key));
	}

	public Set<String> getN(String key) {
		return flatten(match(key));
	}

	@Override
	public Iterator<Entry<String, Set<String>>> iterator() {
		return new KVIterator(qps);
	}

	public static class KVIterator implements Iterator<Map.Entry<String, Set<String>>> {

		private final Iterator<Map.Entry<String, Set<String>>> i;

		public KVIterator(MultivaluedMap<String, String> qps) {
			super();
			Map<String, Set<String>> flattened = new HashMap<>();
			for (String key : qps.keySet()) {
				flattened.put(key, flatten(qps, key));
			}
			i = flattened.entrySet().iterator();
		}

		@Override
		public boolean hasNext() {
			return i.hasNext();
		}

		@Override
		public Entry<String, Set<String>> next() {
			return i.next();
		}

	}

	/**
	 * @param objects - better be sorted by date added...
	 * @return pruned list
	 */
	public List<STIXObject> retainVersion(List<STIXObject> objects) {
		if ((objects == null) || objects.isEmpty() || isAll()) {
			return objects;
		}
		Set<STIXObject> retained = new TreeSet<>((o0, o1) -> o0.getVersion().compareTo(o1.getVersion()));
		if (isFirst()) {
			retained.add(objects.get(0));
		}
		if (isLast()) {
			retained.add(objects.get(objects.size() - 1));
		}
		Set<String> version = getVersion();
		if ((version != null) && !version.isEmpty()) {
			objects.stream().filter(o -> version.contains(o.getVersion())).forEach(o -> retained.add(o));
		}
		return new ArrayList<>(retained);
	}

	@Override
	public String toString() {
		return qps.toString();
	}
}
