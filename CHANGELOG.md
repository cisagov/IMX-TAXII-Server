## 1.0.0 (2026-11-06)

### Bug Fixes

* stabilize legacy CI and validate image builds 74c0ce2
* support restricted scanner users and public image builds 8e54256

## 1.4.4 (2026-09-10)

### Bug Fixes

* accept certificates when CA certificate is in truststore df5e2b3
* ensure that mutual TLS users are in the local database b5c399c
* leave password blank for mutual TLS users dde0e69
* update documentation for mutual TLS to include using an external certificate authority 9c486fb

## 1.4.3 (2026-09-04)

### Bug Fixes

* add mirror for malware behavior catalog 5ff31f7

## 1.4.2 (2026-08-21)

### Bug Fixes

* if github credentials expire, don't delete what has been downloaded 7b062f1

## 1.4.1 (2026-08-13)

### Bug Fixes

* add oca-iob stix extensions to mirrored objects 77be137
* load oca-iob extensions and schemas from stix-extensions repo e8e16b5
* missing line comment e6b9cf8

## 1.4.0 (2026-08-04)

### Features

* code changes for switch to opensearch a35e39e

### Bug Fixes

* add incident mapping 8200a84
* add offest of 0 to mirrored schemas bf9f99f
* add specific jakarta annotations library 70c1fa6
* change references to es8 package cb4eb83
* change taxii-data volume name to permit migration fa01ec4
* remove remaining references to Elasticsearch 561d250
* rename ES* classes to OS* ca6a40a

## 1.3.4 (2026-07-20)

### Bug Fixes

* add offest of 0 to mirrored schemas 8bf5e15
* comment out mirroring from github by default 24226ff
* fix failed search of large github mirrored data sets 866ef28
* implemented searchWithRange for sqllite d7851f8
* improve logging of errors from GitHub 635f169

## 1.3.3 (2026-07-13)

### Bug Fixes

* only override protocol if X-Forwarded-Proto header is found 4d81174

## 1.3.2 (2026-07-10)

### Bug Fixes

* rename schema export file to more meaningful name 64571bb
* update broken junit tests and remove extra files d903c5f

## 1.3.1 (2026-07-01)

### Bug Fixes

* patch cti4j2-ce fasterxml.jackson 390fd4b
* update validator dockerfile. patch validate mixin fasterxml.jackson c3b4a8a

## 1.3.0 (2026-06-30)

### Features

* add IEP and PAP marking extension definition objects e3f1166
* added override to Mapping object 352046e

### Bug Fixes

* mitre-attack api root has some large objects, increase max length 90d3a9b
* removed unused code 7f38401

## 1.2.1 (2026-06-29)

### Bug Fixes

* increase max length of mitre-attack api root 8e3cb78

## 1.2.0 (2026-06-23)

### Features

* added mirroring of oca-iob and mitre-attack STIX content 21732fd

## 1.1.2 (2026-06-15)

### Bug Fixes

* changed GITLAB_TOKEN to GITHUB_TOKEN 1372802
* Issue with removal of internal keystore. 75f5f27

## 1.1.1 (2026-06-12)

### Bug Fixes

* issue with removal of internal keystore a913471

<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

## 1.1.0 (2026-06-01)

### Features

* add semantic release c8502e3
