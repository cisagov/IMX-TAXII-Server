/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.method.impl;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.Level;
import org.eclipse.jetty.http.HttpStatus;

import com.cisa.cti4j2.Timestamp;
import com.cisa.cti4j2.Type;
import com.cisa.taxii4j2.auth.data.Fragment;
import com.cisa.taxii4j2.auth.data.Lenient;
import com.cisa.taxii4j2.auth.data.RWCollection;
import com.cisa.taxii4j2.auth.method.PropsAuthConfig;
import com.cisa.taxii4j2.auth.method.RootCollectionRead;
import com.cisa.taxii4j2.data.Collections;
import com.cisa.taxii4j2.data.Collections.Collection;
import com.cisa.taxii4j2.data.Discovery;
import com.cisa.taxii4j2.data.Envelope;
import com.cisa.taxii4j2.data.Error;
import com.cisa.taxii4j2.data.Filters;
import com.cisa.taxii4j2.data.Status;
import com.cisa.taxii4j2.data.Status.Details;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.data.impl.TAXIIConfig;
import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.method.response.ApiRootResponse;
import com.cisa.taxii4j2.method.response.CollectionResponse;
import com.cisa.taxii4j2.method.response.CollectionsResponse;
import com.cisa.taxii4j2.method.response.DiscoveryResponse;
import com.cisa.taxii4j2.method.response.EnvelopeResponse;
import com.cisa.taxii4j2.method.response.ManifestResponse;
import com.cisa.taxii4j2.method.response.StatusResponse;
import com.cisa.taxii4j2.method.response.VersionsResponse;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;

@Singleton
public class TAXIIImpl implements TAXII {

	protected final RootCollectionRead auth;
	protected final Statuses statuses;

	private class Pending {

		public final String statusId;
		public final String cId;
		public final List<STIXObject> storables;
		public final String refresh;
		public final Set<Lenient> lenients;
		public final boolean addToCommonCollection;

		public Pending(String statusId, String cId, List<STIXObject> storables, String refresh, Set<Lenient> lenients, boolean addToCommonCollection) {

			super();

			try {
				UUID.fromString(cId);
			} catch (IllegalArgumentException e) {
				throw new InternalServerErrorException(String.format("Pending<ctor>: %s not UUID", cId), e);
			}

			this.statusId = statusId;
			this.cId = cId;
			this.storables = storables;
			this.refresh = refresh;
			this.lenients = lenients;
			this.addToCommonCollection = addToCommonCollection;

		}

	}

	private final BlockingDeque<Pending> pendings = new LinkedBlockingDeque<>();

	private final Thread poster = new Thread("poster") {
		@Override
		public void run() {
			while (!interrupted()) {
				try {
					post(pendings.takeFirst());
				} catch (Exception e) {
					logger.log(Level.WARN, "TAXIIImpl.poster", e);
				}
			}
		}
	};

	protected void post(Pending toDo) {

		List<STIXObject> storables = toDo.storables;
		String cId = toDo.cId;
		String statusId = toDo.statusId;
		Set<Lenient> lenients = toDo.lenients;

		logger.info(String.format("posting %s to %s", storables.size(), cId));

		/*
		 * Opportunity to modify object list (and the objects within)...
		 */
		for (PreValidator preValidator : preValidators) {
			preValidator.preValidate(storables, cId, statusId);
		}

		for (STIXObject storable : storables) {

			String id = storable.getId();
			String version = storable.getVersion();

			if (storable.getStixType().contains("indicator")) {
					ObjectMapper oMapper = new ObjectMapper();
					Map map = oMapper.convertValue(storable, Map.class);
					String temp = map.get("pattern").toString();
					temp = temp.replaceAll("\\\\\\\\", "randomreplacestring").replaceAll("\\\\", "\\\\\\\\").replaceAll("randomreplacestring", "\\\\\\\\");
					map.put("pattern", temp);

					storable = oMapper.convertValue(map, STIXObject.class);
				}

			try {

				ValidationResults vrs = validate(lenients, storable, cId);
				List<String> messages = vrs.messages;

				if (vrs.fail) {
					statuses.update(statusId, Status.SFP.failure, new Details(id, version, pretty(messages)));
					continue;
				}

				Status.SFP sfp = Status.SFP.success;
				// The type check is superfluous now, since only marking definitions will have addToCommonCollection set to true.
				if (toDo.addToCommonCollection && storable.getType() == Type.MARKING_DEFINITION && markingDefCId != null) {
					storable.setDate_added(markingDefCId, new Timestamp());
				}
				if (objects.create(storable, cId, Action.REPLACE_SCOS.test(lenients))) {
					messages.add("created");
				} else if (Action.DONT_CHECK_DUPLICATES.test(lenients)) {
					messages.add("duplicate collection/object/version");
					if (Action.DONT_FAIL_DUPLICATES.test(lenients)) {
						sfp = Status.SFP.failure;
					}
				}
				statuses.update(statusId, sfp, new Details(id, version, pretty(messages)));

			} catch (Exception e) {
				e.printStackTrace();
				try {
					statuses.update(statusId, Status.SFP.failure, new Details(id, version, e.getMessage()));
				} catch (Exception e1) {
					logger.log(Level.FATAL, "OSObjects.create", e1);
				}
			}
		}
		String refresh = toDo.refresh;
		if (refresh != null) {
			objects.refresh(refresh);
		}
	}

	public enum Action implements Lenient {

		DONT_RESPECT_CREATOR, DONT_FAIL_CREATOR_CONFLICTS, //
		DONT_CHECK_REVOKED, DONT_FAIL_IF_REVOKED, //
		DONT_CHECK_CREATED, DONT_FAIL_CREATED_MISMATCH,
		REPLACE_SCOS(true), //
		DONT_CHECK_DUPLICATES, DONT_FAIL_DUPLICATES; //

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

	private String pretty(List<String> messages) {
		return (messages.isEmpty()) ? null : messages.stream().reduce("", (prev, curr) -> prev + curr + "\n");
	}

	protected final Objects objects;
	private final Manifests manifests;
	private String markingDefCId = null;

	@Inject
	public TAXIIImpl(Objects objects, Manifests manifests, RootCollectionRead auth, Statuses statuses) {

		super();

		logger.info("TAXIIImpl.<init>");

		this.objects = objects;
		this.manifests = manifests;

		this.auth = auth;
		this.statuses = statuses;

		/*
		 * fail objects without id/version
		 */
		addPreValidator(new PreValidator() {

			@Override
			public void preValidate(List<STIXObject> storables, String cId, String statusId) {
				Iterator<STIXObject> iStorable = storables.iterator();
				while (iStorable.hasNext()) {
					STIXObject storable = iStorable.next();
					String id = storable.getId();
					String version = storable.getVersion();
					if ((id == null) || (version == null)) {
						statuses.update(statusId, Status.SFP.failure,
								new Details(id, version, "missing id or version"));
						iStorable.remove();
					}
				}
			}

		});

		/*
		 * conditionally flag / fail revoked objects
		 */
		addValidator(new Validator() {

			@Override
			public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients) {
				return objects.read(storable.getId()).stream().filter(p -> !p.isOrphan()).anyMatch(p -> {
					/*
					 * revoked is NA for SCOs (they can't be revoked)
					 */
					try {
						return p.isRevoked();
					} catch (IllegalArgumentException e) {
						return false;
					}
				}) ? java.util.Collections.singletonList("previously revoked") : java.util.Collections.emptyList();
			}

			@Override
			public boolean getCheck(Set<Lenient> lenients) {
				return Action.DONT_CHECK_REVOKED.test(lenients);
			}

			@Override
			public boolean getFail(Set<Lenient> lenients) {
				return Action.DONT_FAIL_IF_REVOKED.test(lenients);
			}

		});

		/*
		 * conditionally flag / fail versions with different creators
		 */
		addValidator(new Validator() {

			@Override
			public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients) {
				List<STIXObject> prevs = objects.read(storable.getId());
				prevs.add(storable); // Include the created_by_ref of the new object.
				List<STIXObject> hasCreator = prevs.stream().filter(o -> {
					/*
					 * created_by_ref is NA for SCOs (they have no creator)...
					 */
					try {
						return o.getCreated_by_ref() != null;
					} catch (IllegalArgumentException e) {
						return false;
					}
				}).collect(Collectors.toList());
				/*
				 * either they're all null or, if all non-null all of the same value
				 */
				return (hasCreator.isEmpty()) || ((hasCreator.size() == prevs.size())
						&& (hasCreator.stream().collect(Collectors.groupingBy(o -> o.getCreated_by_ref())).size() == 1))
								? java.util.Collections.emptyList()
								: java.util.Collections.singletonList("created_by_ref mismatch");
			}

			@Override
			public boolean getCheck(Set<Lenient> lenients) {
				return Action.DONT_RESPECT_CREATOR.test(lenients);
			}

			@Override
			public boolean getFail(Set<Lenient> lenients) {
				return Action.DONT_FAIL_CREATOR_CONFLICTS.test(lenients);
			}

		});

		/*
		 * EOS-7043 Validate created timestamps in versioned objects
		 * Should there be a lenient flag for this?
		 */
		addValidator( new Validator() {

			@Override
			public List<String> validate(STIXObject storable, String cId, Set<Lenient> lenients) {
				// Get a sorted list of the exiting versions.
				List<STIXObject> objs = objects.read(storable.getId());
				objs.add(storable);
				objs = objs.stream().sorted().toList();

				// Check that there is not more than one distinct created value.
				List<String> createds = objs.stream().filter(o -> {
					try {
						return o.getCreated() != null;
					} catch (IllegalArgumentException e) {
						return false;
					}
				}).map(STIXObject::getCreated).distinct().toList();
				return (createds.isEmpty() || (createds.size() == 1))
						? java.util.Collections.emptyList()
						: java.util.Collections.singletonList("created timestamp mismatch") ;

				/* Should we do any checks for modified timestamp?
				// Check that all version have a unique modified date
				List<String> modifieds = objs.stream().filter(o -> {
					try {
						return o.getModified() != null;
					} catch (IllegalArgumentException e) {
						return false;
					}
				}).map(STIXObject::getModified).toList();
				if (!modifieds.isEmpty()) {
					if (modifieds.stream().distinct().toList().size() != modifieds.size())
						messages.add("duplicate modified timestamps found");
					if (!modifieds.get(modifieds.size() - 1).equals(storable.getModified()))
						messages.add("new version modified timestamp earlier than previous");
				}
				*/
			}

			@Override
			public boolean getCheck(Set<Lenient> lenients) {
				return Action.DONT_CHECK_CREATED.test(lenients);
			}

			@Override
			public boolean getFail(Set<Lenient> lenients) {
				return Action.DONT_FAIL_CREATED_MISMATCH.test(lenients);
			}

		});

		// EOS-6264 Add marking definitions also to cti-stix-common-objects/marking-definitions
		try {
			Collection mdc = _collection("cti-stix-common-objects", "marking-definition");
			if (mdc != null) {
				markingDefCId = mdc.getId();
				logger.info(String.format("Found marking definition collection id: %s", markingDefCId));
			}
		}
		catch (NotFoundException e) {
			logger.warn("Common marking-definition collection not loaded into TAXII server");
			markingDefCId = null;
		}
		catch (Exception e) {
			logger.error("Error looking up marking-definition collection", e);
			markingDefCId = null;
		}

		poster.start();

	}

	public DiscoveryResponse discover(URI baseUri) {
		List<Fragment> fragments = auth.listFragments();
		List<String> apiRoots = fragments.stream()
				.map(f -> baseUri.resolve(f.getFragment() + "/").toString())
				.collect(Collectors.toList());
		return new DiscoveryResponse(new Discovery(Discovery.getInstance(), apiRoots));
	}

	@Override
	public ApiRootResponse apiRoot(String fragment) {
		required(fragment);
		return new ApiRootResponse(auth.readFragment(fragment).getApiRoot());
	}

	@Override
	public CollectionsResponse collections(String fragment) {
		required(fragment);
		Collections cs = new Collections();
		List<RWCollection> rws = auth.readFragment(fragment).getRws();
		if (rws != null) {
			for (RWCollection rw : rws) {
				cs.add(auth.readCollection(rw.getId()));
			}
		}
		return new CollectionsResponse(cs);
	}

	@Override
	public CollectionResponse collection(String fragment, String cId) {
		required(fragment, cId);
		return new CollectionResponse(_collection(fragment, cId));
	}

	private Collection _collection(String fragment, String cId) {
		required(fragment, cId);
		Collection c = auth.readCollection(cId);
		List<RWCollection> rws = auth.readFragment(fragment).getRws();
		if (rws == null) {
			rws = java.util.Collections.emptyList();
		}
		int index = java.util.Collections.binarySearch(rws, new RWCollection(c.getId()));
		if (index < 0) {
			throw new NotFoundException(String.format("collection %s not on api root %s", cId, fragment));
		}
		return auth.readCollection(rws.get(index).getId()); // (c, rws.get(index));
	}

	@Override
	public ManifestResponse manifest(String fragment, String cId, Filters filters) {
		required(fragment, cId);
		Collection c = _collection(fragment, cId);
		if (!c.isCan_read()) {
			throw new ForbiddenException();
		}
		return new ManifestResponse(
				manifests.read(c.getId(), filters, auth.readFragment(fragment).getApiRoot().getMax_content_length()));
	}

	@Override
	public VersionsResponse versions(String fragment, String cId, String oId, Filters filters) {
		required(fragment, cId);
		Collection c = _collection(fragment, cId);
		if (!c.isCan_read()) {
			throw new ForbiddenException();
		}
		return new VersionsResponse(manifests.versions(c.getId(), oId, filters,
				auth.readFragment(fragment).getApiRoot().getMax_content_length()));
	}

	@Override
	public EnvelopeResponse objects(String fragment, String cId, Filters filters) {
		required(fragment, cId);
		Collection c = _collection(fragment, cId);
		if (!c.isCan_read()) {
			return new EnvelopeResponse(new Error(String.format("reading %s/%s forbidden", fragment, cId),
					Response.Status.FORBIDDEN.getStatusCode()));
		}
		return new EnvelopeResponse(
				objects.envelope(c.getId(), filters, auth.readFragment(fragment).getApiRoot().getMax_content_length())
						.removeMyX_());
	}

	@Override
	public EnvelopeResponse objects(String fragment, String cId, String oId, Filters filters) {
		required(fragment, cId);
		Collection c = _collection(fragment, cId);
		if (!c.isCan_read()) {
			throw new ForbiddenException();
		}
		if (filters.getId() != null) {
			return new EnvelopeResponse(new Error("Read.objects: filter facet must null", Response.Status.BAD_REQUEST));
		}
		return objects(fragment, c.getId(), filters.setId(true, oId));
	}

	public StatusResponse status(String fragment, String id) {
		required(fragment);
		return new StatusResponse(statuses.read(id));
	}

	@Override
	public void close() throws IOException {
		auth.close();
		statuses.close();
	}

	@Override
	public StatusResponse postObjects(String fragment, String cId, Envelope envelope) {

		required(fragment, cId);

		Collection c = _collection(fragment, cId);
		if (!c.isCan_write()) {
			throw new ForbiddenException();
		}
		cId = c.getId();

		boolean addToCommonCollection = ! fragment.equals("test-root");

		List<STIXObject> storables = envelope.getObjects();
		if ((storables == null) || storables.isEmpty()) {
			return new StatusResponse(statuses.create(0));
		}

		StringBuilder d = new StringBuilder();
		for (STIXObject storable : storables) {
			try {
				storable.getId();
				storable.getVersion();
			} catch (Exception e) {
				if (d.length() > 0) {
					d.append('\n');
				}
				d.append(storable.toString());
			}
		}
		if (d.length() > 0) {
			d.append(":\n missing id(s) and/or version(s)");
			return new StatusResponse(new Error(d.toString(), HttpStatus.UNPROCESSABLE_ENTITY_422));
		}

		Fragment f = auth.readFragment(fragment);
		Set<Lenient> skips = f.getRw(cId).getLenients();
		if (skips == null) {
			skips = f.getLenients();
		}

		Status status = statuses.create(storables.size());
		try {
			Map<String, List<STIXObject>> byType = storables.stream()
					.collect(Collectors.groupingBy(s -> s.getStixType()));
			String type = Type.EXTENSION_DEFINITION.toSTIXType();
			List<STIXObject> group = byType.remove(type);
			if (group != null) {
				pendings.putLast(new Pending(status.getId(), cId, group, type, skips, false));
			}
			type = Type.MARKING_DEFINITION.toSTIXType();
			group = byType.remove(type);
			if (group != null) {
				pendings.putLast(new Pending(status.getId(), cId, group, type, skips, addToCommonCollection));
			}
			group = byType.values().stream().flatMap(java.util.Collection::stream).collect(Collectors.toList());
			pendings.putLast(new Pending(status.getId(), cId, group, null, skips, false));
		} catch (Exception e) {
			logger.log(Level.WARN, "TAXIIImpl.postObjects", e);
		}

		return new StatusResponse(status);
	}

	@Override
	public void deleteObjects(String fragment, String cId, String oId, Filters filters) {
		required(fragment, cId);
		Collection c = _collection(fragment, cId);
		if (c.isCan_read() ^ c.isCan_write()) {
			/*
			 * read only or write only
			 */
			throw new ForbiddenException();
		}
		if (!c.isCan_read() && !c.isCan_write()) {
			/*
			 * no read / no write
			 */
			throw new NotFoundException();
		}
		objects.delete(c.getId(), oId, filters);
	}

	private final List<PreValidator> preValidators = new ArrayList<>();

	@Override
	public TAXII addPreValidator(PreValidator helper) {
		preValidators.add(helper);
		return this;
	}

	private final List<Validator> validators = new ArrayList<>();

	@Override
	public TAXII addValidator(Validator validator) {
		validators.add(validator);
		return this;
	}

	@Override
	public ValidationResults validate(Set<Lenient> lenients, STIXObject storable, String cId) {
		List<String> messages = new ArrayList<>();
		boolean fail = false;
		for (Validator validator : validators) {
			if (validator.getCheck(lenients)) {
				List<String> _messages = validator.validate(storable, cId, lenients);
				if ((_messages != null) && !_messages.isEmpty()) {
					messages.addAll(_messages);
					fail |= validator.getFail(lenients);
				}
			}
		}
		return new ValidationResults(messages, fail);
	}

	private static TAXII instance;

	public static TAXII instance() {
		if (instance == null) {
			instance = TAXIIConfig.serviceLocator().create(TAXIIImpl.class);
		}
		return instance;
	}

}
