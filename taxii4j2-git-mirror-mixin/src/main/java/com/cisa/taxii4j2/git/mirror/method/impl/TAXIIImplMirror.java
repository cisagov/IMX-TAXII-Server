/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.git.mirror.method.impl;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;

import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.taxii4j2.data.Status.Details;
import com.cisa.taxii4j2.data.Status.SFP;
import com.cisa.taxii4j2.data.impl.STIXObject;
import com.cisa.taxii4j2.git.mirror.GitHubRepo;
import com.cisa.taxii4j2.git.mirror.GitHubRepos;
import com.cisa.taxii4j2.git.mirror.Mapping;
import com.cisa.taxii4j2.git.mirror.method.TAXIIMirror;
import com.cisa.taxii4j2.method.TAXII;
import com.cisa.taxii4j2.method.TAXII.PreValidator;
import com.cisa.taxii4j2.method.impl.Objects;
import com.cisa.taxii4j2.method.impl.Statuses;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

@Singleton
public class TAXIIImplMirror implements TAXIIMirror {

	@Inject
	public TAXIIImplMirror() {
		super();
		LogManager.getLogger(TAXIIImplMirror.class).info("TAXIIImplMirror.<init>");
		start();
	}

	public static TAXII compose(TAXII taxiiSlim, Objects objects, Statuses statuses) {

		/*
		 * automagically add mirror mentions
		 */
		taxiiSlim.addPreValidator(new PreValidator() {

			@Override
			public void preValidate(List<STIXObject> storables, String cId, String statusId) {
				Set<String> types = new HashSet<>();
				for (STIXObject storable : storables) {
					for (String mention : storable.mentionedIds()) {
						List<STIXObject> mentions = objects.read(mention);
						Optional<STIXObject> optional = mentions.stream().filter(p -> GitHubRepos.getRef(p) != null)
								.findAny();
						if (optional.isPresent()) {
							STIXObject ref = optional.get();
							objects.create(ref, cId, true);
							types.add(ref.getStixType());
						}
					}
				}
				if (!types.isEmpty()) {
					objects.refresh(types.toArray(String[]::new));
				}
			}

		});

		/*
		 * free pass on mirror objects
		 */
		taxiiSlim.addPreValidator(new PreValidator() {

			@Override
			public void preValidate(List<STIXObject> storables, String cId, String statusId) {
				Iterator<STIXObject> iStorable = storables.iterator();
				while (iStorable.hasNext()) {
					STIXObject storable = iStorable.next();
					String id = storable.getId();
					Optional<STIXObject> optional = objects.read(id).stream().filter(p -> GitHubRepos.getRef(p) != null)
							.findAny();
					if (optional.isPresent()) {
						objects.create(optional.get(), cId, true);
						String version = storable.getVersion();
						statuses.update(statusId, SFP.success, new Details(id, version,
								String.format("%s/%s is a mirror; no validation performed", id, version)));
						iStorable.remove();
					}
				}
			}

		});

		return taxiiSlim;

	}

	@Override
	public MirrorState mirrorCreate(GitHubRepo filter) {
		return GitHubRepos.create(filter);
	}

	@Override
	public MirrorState mirrorUpdate(UUID uuid) {
		return GitHubRepos.update(uuid);
	}

	@Override
	public List<MirrorState> mirrorList() {
		return GitHubRepos.list();
	}

	@Override
	public JsonNode mirrorSchema(String id) {
		return GitHubRepos.getSchema(id);
	}

	@Override
	public MirrorState mirrorAdd(UUID uuid, Mapping mapping) {
		return GitHubRepos.add(uuid, mapping);
	}

	@Override
	public MirrorState mirrorRemove(UUID uuid, UUID mUuid) {
		return GitHubRepos.remove(uuid, mUuid);
	}

	@Override
	public void start() {
		GitHubRepos.start();
	}

	@Override
	public MirrorState mirrorRead(UUID uuid) {
		return GitHubRepos.read(uuid);
	}

	@Override
	public void mirrorRemove(UUID uuid) {
		GitHubRepos.remove(uuid);
	}

}
