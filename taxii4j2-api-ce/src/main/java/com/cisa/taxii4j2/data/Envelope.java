/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.data;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.cisa.cti4j2.Timestamp;
import com.cisa.taxii4j2.data.impl.FirstLast;
import com.cisa.taxii4j2.data.impl.JSONSTIXObject;
import com.cisa.taxii4j2.data.impl.STIXObject;

@JsonInclude(Include.NON_NULL)
public class Envelope extends FirstLast implements Iterable<STIXObject> {

	private static final String moreKey = "more";
	private static final String nextKey = "next";
	private static final String objectsKey = "objects";

	@JsonProperty(moreKey)
	private Boolean more;

	@JsonProperty(nextKey)
	private String next;

	/**
	 * For Object and Manifest Endpoints, objects returned MUST be sorted in
	 * ascending order by the date it was added. Meaning, the most recently added
	 * object is last in the list.
	 */
	@JsonProperty(objectsKey)
	private List<STIXObject> objects;

	@JsonCreator
	public Envelope(@JsonProperty(value = moreKey, required = false) Boolean more,
			@JsonProperty(value = nextKey, required = false) String next,
			@JsonProperty(value = objectsKey, required = false) List<STIXObject> objects) {
		this(more, next, objects, null);
	}

	public Envelope(Boolean more, String next, List<STIXObject> objects, String cId) {
		super(Envelope.class);
		setMore(more);
		setNext(next);
		setObjects(objects, cId);
	}

	public Envelope(List<STIXObject> objects) {
		this(false, null, objects, null);
	}

	private static List<STIXObject> objects(JsonNode array) {
		if (!array.isArray()) {
			return null;
		}
		List<STIXObject> objects = null;
		try {
			Iterator<JsonNode> iObject = array.elements();
			objects = new ArrayList<>();
			while (iObject.hasNext()) {
				objects.add(new JSONSTIXObject(iObject.next()));
			}
		} catch (Exception e) {

		}
		return objects;
	}

	public static Envelope create(JsonNode root) {

		Boolean more = null;
		try {
			more = root.get(moreKey).asBoolean();
		} catch (Exception e) {

		}

		String next = null;
		try {
			next = root.get(nextKey).asText();
		} catch (Exception e) {

		}

		List<STIXObject> objects = null;
		if (root.isObject()) {
			try {
				objects = objects(root.get(objectsKey));
			} catch (Exception e) {
				STIXObject object = new JSONSTIXObject(root);
				try {
					object.getId();
					object.getVersion();
					objects = java.util.Collections.singletonList(object);
				} catch (Exception e1) {

				}
			}
		} else if (root.isArray()) {
			try {
				objects = objects(root);
			} catch (Exception e) {

			}
		}

		return new Envelope(more, next, objects);

//		/*
//		 * try easy way first...
//		 */
//		try {
//			return JSON.convertValue(root, Envelope.class);
//		} catch (Exception e) {
//
//		}
//
//		/*
//		 * if it's a bundle, strip it down to an envelope...
//		 */
//		JsonNode type = root.get(CommonProperty.TYPE.getJsonKey());
//		if ((type != null) && type.asText().equals(Type.BUNDLE.toSTIXType())) {
//			ObjectNode object = ObjectNode.class.cast(root);
//			object.remove(CommonProperty.TYPE.getJsonKey());
//			object.remove(CommonProperty.ID.getJsonKey());
//			try {
//				return JSON.convertValue(object, Envelope.class);
//			} catch (Exception e) {
//
//			}
//		}
//
//		/*
//		 * maybe it's just an array of objects...
//		 */
//		if (root.isArray()) {
//			try {
//				List<STIXObject> objects = new ArrayList<>();
//				Iterator<JsonNode> iObject = root.elements();
//				while (iObject.hasNext()) {
//					objects.add(JSON.convertValue(iObject.next(), STIXObject.class));
//				}
//				return new Envelope(objects);
//			} catch (Exception e) {
//
//			}
//		}
//
//		/*
//		 * last chance, see if it's a single object...
//		 */
//		try {
//			return new Envelope(java.util.Collections.singletonList(JSON.convertValue(root, STIXObject.class)));
//		} catch (Exception e) {
//
//		}
//		throw new IllegalArgumentException();

	}

	@JsonIgnore
	public Boolean getMore() {
		return (more != null) ? more : false;
	}

	public String getNext() {
		return next;
	}

	public List<STIXObject> getObjects() {
		return (objects != null) ? java.util.Collections.unmodifiableList(objects) : null;
	}

	public Envelope add(List<STIXObject> objects) {
		if ((objects != null) && !objects.isEmpty()) {
			if (this.objects == null) {
				this.objects = new ArrayList<>(objects);
			} else {
				this.objects.addAll(objects);
			}
		}
		return this;
	}

	@Override
	public Iterator<STIXObject> iterator() {
		return new Iterator<STIXObject>() {

			private Iterator<STIXObject> i = (objects != null) ? objects.iterator() : null;

			@Override
			public boolean hasNext() {
				return i != null;
			}

			@Override
			public STIXObject next() {
				STIXObject s = i.next();
				if (!i.hasNext()) {
					i = null;
				}
				return s;
			}
		};
	}

	public Envelope setMore(Boolean more) {
		this.more = ((more != null) && more) ? true : null;
		return this;
	}

	public Envelope setNext(String next) {
		this.next = next;
		return this;
	}

	public Envelope setObjects(List<STIXObject> objects, String cId) {
		if ((objects == null) || objects.isEmpty()) {
			clearFirstLast();
			this.objects = null;
			return this;
		}
		Timestamp first = (cId != null) ? objects.get(0).getDate_added(cId) : null;
		Timestamp last = (cId != null) ? objects.get(objects.size() - 1).getDate_added(cId) : null;
		setFirstLast(first, last);
		this.objects = new ArrayList<>(objects);
		return this;
	}

	public Envelope removeMyX_() {
		if (objects != null) {
			objects.forEach(o -> o.removeMyX_());
		}
		return this;
	}

	@JsonIgnore
	public boolean isEmpty() {
		return objects == null;
	}

	@JsonIgnore
	public Object size() {
		return (objects != null) ? objects.size() : 0;
	}

}
