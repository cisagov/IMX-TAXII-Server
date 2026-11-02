<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

This folder contains schemas that should be uploaded manually via the API, rather than mirrored from github

* extension-definition--3a65884d-005a-4290-8335-cb2d778a83ce.json and isa-acs-3-0.json contain the ACS marking definition extension.
AIS added new values for the sharability field, that were not included in the schema published via github. This would cause the TAXII
server to reject ACS marking definition objects required by AIS. If and when the schema is updated on github, these can be removed.
