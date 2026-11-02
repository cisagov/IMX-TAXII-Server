# Copyright 2026 Cybersecurity and Infrastructure Security Agency (CISA)
#
# This software is released to the public domain under 17 U.S.C. § 105.
# The Apache 2.0 license applies to the extent permitted by applicable law,
# and for the benefit of international users.

from flask import Flask
app = Flask(__name__)

from flask import request, jsonify

import json
from types import SimpleNamespace
from stix2validator import validate_instance, ValidationOptions, print_results

import requests
requests.urllib3.disable_warnings()
requests.get = lambda url, **kwargs: requests.request(
    method="GET", url=url, verify=False, **kwargs
)

import jsonschema
import os


#s = '{ "created": "2021-01-17T22:09:20.000Z", "created_by_ref": "identity--f9d4d08b-e331-47de-9d6f-aecf821f25bc", "description": "MalwareDownload_Generic", "id": "indicator--c6877727-fb38-45a0-87a7-2ca43052c498", "modified": "2021-01-17T22:09:20.000Z", "object_marking_refs": [ "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9" ], "spec_version": "2.1", "type": "indicator", "valid_from": "2021-01-17T22:09:20.000000Z" }'
#s = '{ "created": "not a time", "created_by_ref": "identity--abc", "description": "MalwareDownload_Generic", "id": "indicator--c6877727-fb38-45a0-87a7-2ca43052c498", "modified": "2021-01-17T22:09:20.000Z", "object_marking_refs": [ "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9" ], "spec_version": "2.1", "type": "indicator", "valid_from": "2021-01-17T22:09:20.000000Z" }'
#s = '[{ "created": "not a time", "created_by_ref": "identity--abc", "description": "MalwareDownload_Generic", "id": "indicator--c6877727-fb38-45a0-87a7-2ca43052c498", "modified": "2021-01-17T22:09:20.000Z", "object_marking_refs": [ "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9" ], "spec_version": "2.1", "type": "indicator", "valid_from": "2021-01-17T22:09:20.000000Z" }]'
#s = '{"objects": [{ "created": "not a time", "created_by_ref": "identity--abc", "description": "MalwareDownload_Generic", "id": "indicator--c6877727-fb38-45a0-87a7-2ca43052c498", "modified": "2021-01-17T22:09:20.000Z", "object_marking_refs": [ "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9" ], "spec_version": "2.1", "type": "indicator", "valid_from": "2021-01-17T22:09:20.000000Z" }, { "created": "not a time", "created_by_ref": "identity--abc", "description": "MalwareDownload_Generic", "id": "indicator--c6877727-fb38-45a0-87a7-2ca43052c498", "modified": "2021-01-17T22:09:20.000Z", "object_marking_refs": [ "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9" ], "spec_version": "2.1", "type": "indicator", "valid_from": "2021-01-17T22:09:20.000000Z" }]}'

def validate_inner(objects, _options):
  errors = []
  warnings = []
  if isinstance(objects, list):
    for object in objects:
      obj_errors, obj_warnings = validate_inner(object, _options)
      errors += obj_errors
      warnings += obj_warnings
  else:
    results = validate_instance(objects, options=_options)
    for error in results.errors:
      ss = str(error).split(': ', 1)
      errors.append({ 'id': ss[0], 'message': ss[1] })
    for warn in results.warnings:
      ss = str(warn).split(': ', 1)
      warnings.append({ 'id': ss[0], 'message': ss[1] })
  return errors, warnings

def validate_outer(source, _options):
  objects = source
  if 'objects' in source:
    objects = source['objects']
  errors, warnings = validate_inner(objects, _options)
  return { 'source': source, 'is_valid': len(errors) == 0, 'errors': errors, 'warnings': warnings }

def options(_options, _version):
  _strict = 'strict' in _options
  _strict_types = 'strict_types' in _options
  _strict_properties = 'strict_properties' in _options
  _schema_dir = _options['schema_dir'] if 'schema_dir' in _options else None
  print("_strict: {}, _strict_types: {}, _strict_properties: {}, _schema_dir: {}".format(
	_strict, _strict_types, _strict_properties, _schema_dir))
  return ValidationOptions(
    version=_version,
    strict=_strict,
    strict_types=_strict_types,
    strict_properties=_strict_properties,
    schema_dir=_schema_dir
    )

@app.route('/test', methods=['GET'])
def test():
    return 'Successfully reached Stix2 Validator'

@app.route('/validate/20', methods = [ 'POST' ])
def validate20():
  return validate("2.0")

@app.route('/validate/21', methods = [ 'POST' ])
def validate21():
  return validate("2.1")

def validate(_version):
  source = request.get_json()
  reply = validate_outer(source['object'], options(source['options'], _version))
  return reply

_taxiiHost = 'localhost:8443'
_username = 'admin'
_password = 'admin'

@app.route('/extensions', methods = [ 'POST' ])
def extensions():
  outer = []
  for k,v in request.get_json().items():

    inner = { 'key': k, 'is_valid': False }
    outer.append(inner)

    taxiiHost = request.args.get('taxiiHost', default=_taxiiHost);
    username = request.args.get('username', default=_username);
    password = request.args.get('password', default=_password);

    response = requests.get(
      'https://{}/ext/v1.0/schema/{}'.format(taxiiHost, k),
      auth=(username, password),
      verify=False
      )

    status_code = response.status_code
    inner['status_code'] = status_code
    if status_code != 200:
      continue;

    try:
      jsonschema.validators.validate(v, response.json())
      inner['is_valid'] = True
    except (jsonschema.exceptions.ValidationError, jsonschema.exceptions.SchemaError) as e:
      inner['message'] = e.message

  return outer


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
