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

WORKDIR /taxii4j2-logging-th
COPY taxii4j2-logging-th/src/ src/
COPY taxii4j2-logging-th/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /cti4j2-th
COPY cti4j2-th/src/ src/
COPY cti4j2-th/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-client-th
COPY taxii4j2-client-th/src/ src/
COPY taxii4j2-client-th/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-binding-sqlite-ce
COPY taxii4j2-binding-sqlite-ce/src/ src/
COPY taxii4j2-binding-sqlite-ce/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-binding-sqlite-th
COPY taxii4j2-binding-sqlite-th/src/ src/
COPY taxii4j2-binding-sqlite-th/pom.xml pom.xml
RUN mvn clean install -Dmaven.test.skip=true

WORKDIR /taxii4j2-proxy-th
COPY taxii4j2-proxy-th/src/ src/
COPY taxii4j2-proxy-th/pom.xml pom.xml
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

COPY --from=build /taxii4j2-proxy-th/target/taxii4j2-proxy-th-0.1-SNAPSHOT.jar /opt/taxii4j2/
COPY --from=build /taxii4j2-proxy-th/target/lib/ /opt/taxii4j2/lib/
#COPY taxii4j2-ce/data/ /opt/taxii4j2/data

RUN mkdir /target
#RUN mkdir /target/logs
RUN chgrp -R 0 /target && chmod -R g=u /target
#RUN mkdir /opt/taxii4j2
RUN mkdir /opt/taxii4j2/data
RUN chgrp -R 0 /opt/taxii4j2 && chmod -R g=u /opt/taxii4j2

ENTRYPOINT [ "java", "-cp", "/opt/taxii4j2/taxii4j2-proxy-th-0.1-SNAPSHOT.jar", "com.cisa.taxii4j2.main.ProxyMicroService" ]
