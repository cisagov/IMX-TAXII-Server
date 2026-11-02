/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.auth.data;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.cisa.taxii4j2.data.ApiRoot;
import com.cisa.taxii4j2.data.impl.DataUtils;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;

@JsonInclude(Include.NON_NULL)
public class Fragment implements Comparable<Fragment> {

	private static final String fragmentKey = "fragment";
	private static final String apiRootKey = "apiRoot";
	private static final String rwsKey = "rws";
	private static final String lenientsKey = "lenients";

	@JsonProperty(fragmentKey)
	protected String fragment;

	@JsonProperty(apiRootKey)
	protected ApiRoot apiRoot;

	@JsonProperty(rwsKey)
	protected List<RWCollection> rws;

	@JsonProperty(lenientsKey)
	protected Set<Lenient> lenients;

	@JsonCreator
	public Fragment(@JsonProperty(value = fragmentKey, required = true) String fragment,
			@JsonProperty(value = apiRootKey, required = true) ApiRoot apiRoot,
			@JsonProperty(value = rwsKey, required = false) List<RWCollection> rws,
			@JsonProperty(value = lenientsKey, required = false) Set<Lenient> lenients) {
		super();
		this.fragment = fragment;
		this.apiRoot = apiRoot;
		this.rws = DataUtils.tidy(rws);
		this.lenients = lenients;
	}

	public Set<Lenient> getLenients() {
		return lenients;
	}

	public Set<Lenient> getLenients(String cId) {
		return getRw(cId).getLenients();
	}

	@JsonIgnore
	public Fragment setLenients(Set<Lenient> values) {
		lenients = !values.isEmpty() ? values : null;
		return this;
	}

	@JsonIgnore
	public Fragment addLenients(Set<Lenient> add) {
		if (add.isEmpty()) {
			return this;
		}
		if (lenients != null) {
			lenients.addAll(add);
		} else {
			lenients = add;
		}
		return this;
	}

	@JsonIgnore
	public Fragment removeLenients(Set<Lenient> values) {
		if (values.isEmpty()) {
			return this;
		}
		if(lenients != null) {
			lenients.removeAll(values);
			if(lenients.isEmpty()) {
				lenients = null;
			}
		}
		return this;
	}

	@JsonIgnore
	public Fragment setLenients(String cId, Set<Lenient> values) {
		getRw(cId).setLenients(values);
		return this;
	}

	@JsonIgnore
	public Fragment addLenients(String cId, Set<Lenient> values) {
		getRw(cId).addLenients(values);
		return this;
	}

	@JsonIgnore
	public Fragment removeLenients(String cId, Set<Lenient> values) {
		getRw(cId).removeLenients(values);
		return this;
	}

	public Fragment addCan_write(String cId, String writer) {
		return add(cId, rw -> {
			rw.addCan_write(writer);
			return this;
		});
	}

	public Fragment addCan_read(String cId, String reader) {
		return add(cId, rw -> {
			rw.addCan_read(reader);
			return this;
		});
	}

	private synchronized Fragment add(String cId, Function<RWCollection, Fragment> f) {
		try {
			UUID.fromString(cId);
		} catch (IllegalArgumentException e) {
			throw new BadRequestException(String.format("Fragment.addRW: %s not UUID", cId), e);
		}
		if (rws == null) {
			return addRW(new RWCollection(cId)).add(cId, f);
		}
		int index = Collections.binarySearch(rws, new RWCollection(cId));
		return (index >= 0) ? f.apply(rws.get(index)) : this;
	}

	private synchronized Fragment remove(String cId, Function<RWCollection, Fragment> f) {
		if (rws == null) {
			return this;
		}
		int index = Collections.binarySearch(rws, new RWCollection(cId));
		if (index < 0) {
			throw new NotFoundException();
		}
		return f.apply(rws.get(index));
	}

	public Fragment removeCan_read(String cId, String reader) {
		return remove(cId, rw -> {
			rw.removeCan_read(reader);
			return this;
		});
	}

	public Fragment removeCan_write(String cId, String writer) {
		return remove(cId, rw -> {
			rw.removeCan_write(writer);
			return this;
		});
	}

	synchronized public Fragment removeRW(String cId) {
		if (rws == null) {
			return this;
		}
		int index = Collections.binarySearch(rws, new RWCollection(cId));
		if (index < 0) {
			throw new NotFoundException();
		}
		rws.remove(index);
		if (rws.isEmpty()) {
			rws = null;
		}
		return this;
	}

	synchronized public Fragment addRW(RWCollection rw) {

		try {
			UUID.fromString(rw.getId());
		} catch (IllegalArgumentException e) {
			throw new BadRequestException(String.format("Fragment.addRW: %s not UUID", rw.getId()));
		}

		if (rws == null) {
			rws = new ArrayList<>();
		}
		int index = Collections.binarySearch(rws, rw);
		if (index < 0) {
			rws.add(-index - 1, rw);
		}
		return this;
	}

	public synchronized Fragment setApiRoot(ApiRoot apiRoot) {
		this.apiRoot = apiRoot;
		return this;
	}

	public List<RWCollection> getRws() {
		return rws;
	}

	public ApiRoot getApiRoot() {
		return apiRoot;
	}

	public String getFragment() {
		return fragment;
	}

	public RWCollection getRw(String cId) {
		if (rws == null) {
			return null;
		}
		int index = java.util.Collections.binarySearch(rws, new RWCollection(cId));
		return (index >= 0) ? rws.get(index) : null;
	}

	@Override
	public int compareTo(Fragment o) {
		return getFragment().compareTo(o.getFragment());
	}

}
