<!--
  ~ Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
  ~
  ~ This software is released to the public domain under 17 U.S.C. § 105.
  ~ The Apache 2.0 license applies to the extent permitted by applicable law,
  ~ and for the benefit of international users.
-->

# taxii4j2-search-mixin

This module adds structured query-based text search capabilities to
STIX object member values.  This expands on the filter-based search
(both from the original TAXII and interoperability standards) to enable
finding arbitrary words and phrases in one or more (or all) members
e.g. *windows foundation class exploitation*
in the `description` member of an attack pattern.

There are two endpoints, both taking the same payload -
a string defined by the Elasticsearch query DSL (see below),
an offset into the search results, and the maximum number
of items to include in the result:

```
"query": {
  "type:ipv4-addr",
  "from": 16,
  "size": 8
}
```

More on this paging capability below.

`POST ext/v1.0/{api-root}/collections/{collection-id}/search`
limits the search context to the api root and collection specified
in the path. `POST ext/v1.0/search` will search all api roots
and collections readable by the request authentication credentials
used. Both endpoints accept standard TAXII endpoint filters as well.

This implementation requires the use of the Elasticsearch
persistence plugin (vice, say SQLite).

## Response

The response contains members echoing the critical request members,
global response size information, and, of course, any found objects...

```
{
  "fcPairs": {
    "Send2A1": [
      "7d476dc7-5c2a-418b-b150-8b07cad20b43"
    ]
  },
  "filters": {},
  "query": {
    "type:ipv4-addr",
    "from": 16,
    "size": 8
  },
  "total": 42,
  "truncated": false,
  "founds": [
    {
      "score": 2.210721,
      "object": {
        "defanged": false,
        "id": "ipv4-addr--0ed94e4b-2195-539d-9aa2-d37f2591a69e",
        "object_marking_refs": [
          "marking-definition--adbfd045-ab70-4c52-8f24-e239e5da4cc7",
          "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb"
        ],
        "spec_version": "2.1",
        "type": "ipv4-addr",
        "value": "198.252.98.184",
        "x_49623f47_60a9_4068_b43d_7e177d46a969_7d476dc7_5c2a_418b_b150_8b07cad20b43": "2024-06-27T16:26:42.775493Z"
      },
      "fcPairs": {
        "Send2A1": [
          "7d476dc7-5c2a-418b-b150-8b07cad20b43"
        ]
      }
    },
    ...
```

The top level member `fcPairs` lists all root / collection pairs searched.
If TAXII standard filters were applied, e.g. `added_after=2024-06-28T00:00:00Z`,
these are echoed in top level `filters` member.
Keep in mind that these constraints are conjoined with the query constraints.

The original query is echoed in the `query` member.
Like many of the CISA TAXII endpoints, the maximum number
of items included in the reply is hard limited in order
to prevent oversized payloads that endanger both server and client integrity.
Hence, the top level `query` element contains an offset `from` and a
chunk size `size` enabling paging through larger result sets.
`total` contains the, well, total number of search results available
**OR** a maximum number supported by Elasticsearch (typically 10000).
If `truncated` is `false`, then `total` is exact and accurate.
If `truncated` is `true`, then an undetermined number of results are
available that is greater than or equal to `total`.
These values, taken in concert, allow a client to display something along
the lines of

displaying results `from` through `from + size - 1` of `total`

and/or

displaying results `from` through `from + size - 1` of more than `total - 1`

`founds` is an array of search hits.
Each has the match score as returned by Elasticsearch (treat these as ordinal values -
higher value implies better match). Hits are sorted in decreasing `score` value
(better matches appear earlier in the list).
`object` is the STIX hit.
The `fcPairs` member inside a hit provides root / collection pairs from which
the object can be retrieved (using the same authentication credentials as the search).

## Queries

The full query DSL can be found
[here](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html).

For flavor, the query described above would be expressed

```
type.keyword:attack-pattern AND description:(windows foundation class exploitation)
```

in which we match exactly (no lexical analysis) the STIX object `type` member
as `attack-pattern` and
favor STIX attack pattern objects which include the most of words `windows`, `foundation`,
`class`, and `exploitation` (in any given order, to be precise).

Recalling that the endpoints take standard TAXII endpoint filters, submitting

```
description:(windows foundation class exploitation)
```

to `ext/v1.0/search?match[type]=attack-pattern` would also suffice.

The DSL is powerful, intuitive, but expansive and, like
Google searching, can be fraught with frustration.
