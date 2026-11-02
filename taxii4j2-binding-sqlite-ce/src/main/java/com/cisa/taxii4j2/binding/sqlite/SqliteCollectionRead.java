/*
 * Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
 *
 * This software is released to the public domain under 17 U.S.C. § 105.
 * The Apache 2.0 license applies to the extent permitted by applicable law,
 * and for the benefit of international users.
 */

package com.cisa.taxii4j2.binding.sqlite;

import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import com.cisa.cti4j2.JSON;
import com.cisa.taxii4j2.data.Collections.Collection;
import com.cisa.taxii4j2.servlet.store.DbBase;
import com.cisa.taxii4j2.servlet.store.DbRootCollectionRead;

import jakarta.inject.Singleton;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;

@Singleton
public class SqliteCollectionRead implements DbRootCollectionRead.CollectionRead {

	@Override
	public Collection readCollection(String cId, DbBase db, String collectionIndex) {
		cId = SqliteBase.quote(cId);
		StringBuilder where = SqliteBase.disjunct(new StringBuilder(), "", Collection.idKey, cId);
		where = SqliteBase.disjunct(where, "", Collection.aliasKey, cId);
		try (Statement statement = db.client(Connection.class).createStatement()) {
			String query = String.format("select %s from %s where %s", SqliteBase.Column.SOURCE, collectionIndex,
					where);
			SqliteBase.logger.debug(query);
			try (ResultSet rs = statement.executeQuery(query)) {
				if (!rs.next()) {
					throw new NotFoundException(String.format("\"%s\" is an unknown collection id or alias", cId));
				}
				return JSON.readValue(rs.getString(1), Collection.class);
			}
		} catch (IOException | SQLException e) {
			throw new InternalServerErrorException(e);
		}
	}

}
