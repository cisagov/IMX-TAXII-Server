# Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
#
# This software is released to the public domain under 17 U.S.C. § 105.
# The Apache 2.0 license applies to the extent permitted by applicable law,
# and for the benefit of international users.
ARG REGISTRY=docker.io/library

FROM $REGISTRY/maven:3.6.3-openjdk-17-slim AS build

WORKDIR /cti4j2-ce
COPY cti4j2-ce/src/ src/
COPY cti4j2-ce/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-api-ce
COPY taxii4j2-api-ce/src/ src/
COPY taxii4j2-api-ce/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-auth-ce
COPY taxii4j2-auth-ce/src/ src/
COPY taxii4j2-auth-ce/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-servlet-ce
COPY taxii4j2-servlet-ce/src/ src/
COPY taxii4j2-servlet-ce/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /cti4j2-th
COPY cti4j2-th/src/ src/
COPY cti4j2-th/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-client-th
COPY taxii4j2-client-th/src/ src/
COPY taxii4j2-client-th/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-logging-th
COPY taxii4j2-logging-th/src/ src/
COPY taxii4j2-logging-th/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-git-api
COPY taxii4j2-git-api/src/ src/
COPY taxii4j2-git-api/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-validate-mixin
COPY taxii4j2-validate-mixin/src/ src/
COPY taxii4j2-validate-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-best-practices-mixin
COPY taxii4j2-best-practices-mixin/src/ src/
COPY taxii4j2-best-practices-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-git-mirror-mixin
COPY taxii4j2-git-mirror-mixin/src/ src/
COPY taxii4j2-git-mirror-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-schema-mixin
COPY taxii4j2-schema-mixin/src/ src/
COPY taxii4j2-schema-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-a1-mixin
COPY taxii4j2-a1-mixin/src/ src/
COPY taxii4j2-a1-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-servlet-th
COPY taxii4j2-servlet-th/src/ src/
COPY taxii4j2-servlet-th/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-admin-th
COPY taxii4j2-admin-th/src/ src/
COPY taxii4j2-admin-th/pom.xml pom.xml
COPY taxii4j2-admin-th/swagger-config.yaml swagger-config.yaml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-binding-es-ce
COPY taxii4j2-binding-es-ce/src/ src/
COPY taxii4j2-binding-es-ce/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-binding-es-th
COPY taxii4j2-binding-es-th/src/ src/
COPY taxii4j2-binding-es-th/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-util-mixin
COPY taxii4j2-util-mixin/src/ src/
COPY taxii4j2-util-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-misp-mixin
COPY taxii4j2-misp-mixin/src/ src/
COPY taxii4j2-misp-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-search-mixin
COPY taxii4j2-search-mixin/src/ src/
COPY taxii4j2-search-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-mount-mixin
COPY taxii4j2-mount-mixin/src/ src/
COPY taxii4j2-mount-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-graph-mixin
COPY taxii4j2-graph-mixin/src/ src/
COPY taxii4j2-graph-mixin/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-main-th
COPY taxii4j2-main-th/src/ src/
COPY taxii4j2-main-th/pom.xml pom.xml
RUN mvn clean package -Dmaven.test.skip=true

# Alpine, does not have ARM version
# FROM eclipse-temurin:17.0.16_8-jre-alpine-3.22
# RUN apk update && apk upgrade && apk add openssl && apk add sqlite && apk add curl

# Ubuntu, more vulnerabilties, but works
# FROM eclipse-temurin:17.0.17_10-jre-noble
# RUN apt update \
#     && apt full-upgrade \
#     && apt install -y openssl \
#     && apt install -y sqlite3 \
#     && apt install -y curl

# RHEL, less vulnerable, but may lead to compatibility issues
FROM $REGISTRY/eclipse-temurin:17.0.17_10-jre-ubi10-minimal
RUN microdnf update -y \
    && microdnf upgrade \
    && microdnf clean all \
    && microdnf install -y openssl \
    && microdnf install -y sqlite \
    && microdnf install -y curl

COPY --from=build /taxii4j2-main-th/target/taxii4j2-main-th-0.1-SNAPSHOT.jar /opt/taxii4j2/
COPY --from=build /taxii4j2-main-th/target/lib/ /opt/taxii4j2/lib/
#COPY taxii4j2-ce/data/ /opt/taxii4j2/data

RUN mkdir /tmp/schema
RUN chgrp -R 0 /tmp/schema && chmod -R g=u /tmp/schema

ENTRYPOINT [ "java", "-cp", "/opt/taxii4j2/taxii4j2-main-th-0.1-SNAPSHOT.jar", "com.cisa.taxii4j2.servlet.THMicroService", "--config", "server.es.properties" ]
# For remote debugging access to the server, uncomment this entrypoint and allow port 8000 in the docker-compose.yml
#ENTRYPOINT [ "java", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000", "-cp", "/opt/taxii4j2/taxii4j2-main-th-0.1-SNAPSHOT.jar", "com.cisa.taxii4j2.servlet.THMicroService", "--config", "server.es.properties" ]
