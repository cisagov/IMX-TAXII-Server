import requests
import pytest
import json
import uuid
from datetime import datetime, timezone
from utils.utils import generate_random_string, read_json_data_from_file
from taxii2client.v21 import ApiRoot

import time

@pytest.mark.parametrize("creds", ["admin", "non_admin"], indirect=True)
class TestTAXIIAPIs:

    def test_server_discovery_with_auth_header(self, creds, logger):
        logger.info("Test: Testing Server Discovery with Auth header")
        host, auth = creds
        url = host + "taxii2/"
        response = requests.get(url, auth=auth, verify=False)
        if response.status_code != 200:
            assert False, "Server does not exist"
        if not response.json():
            assert False, "Server has no API Roots"
        json_body = response.json()
        assert json_body

    def test_api_root_resource(self, creds, logger):
        logger.info("Test: Requesting API Root Resource")
        host, auth = creds

        api_root = "test-root/"
        url = host + "taxii2/"

        response = requests.get(url, auth=auth, verify=False)

        if response.status_code != 200:
            assert False, "Server does not exist"
        if not response.json():
            assert False, "Server has no API Roots"
        json_body = response.json()

        standard_ports = ['80', '443']

        if host.count(":") > 1 and any(port in host for port in standard_ports):  # host url includes the port
            host = host.rsplit(sep=":", maxsplit=1)[0] + '/taxii/v2.1-os/'

        if host+api_root not in json_body['api_roots']:
            assert False, "API Root does not exist"

        response = requests.get(host+api_root, auth=auth, verify=False)

        if response.status_code != 200:
            assert False, "Error retrieving API Root resource"
        if not response.json():
            assert False, "API Root Resource Information missing"

    def test_non_existent_api_root_resource(self, creds, logger):
        logger.info("Test: Requesting Non Existent API Root Resource")
        host, auth = creds

        api_root = host + "foo/"

        response = requests.get(api_root, auth=auth, verify=False)

        if response.status_code != 404:
            assert False, "API Root exists"
        if not response.json():
            assert False, "Server has no API Roots"
        json_body = response.json()

        if "unknown api-root path" in json_body['title']:
            assert True, "API Root does not exist"

    def test_non_existent_object(self, creds, logger):
        logger.info("Test: Requesting Non Existent Object")
        host, auth = creds

        api_root = host + "test-root/"
        object_url = api_root + "collections/fcd2c97e-20aa-4ed0-ac3a-cad8eafad093/objects/indicator--258e7d43-ab46-5081-bd12-bf09ab41b1ee/"

        response = requests.get(object_url, auth=auth, verify=False)

        logger.info(response.status_code)

        if response.status_code != 200:
            assert True, "Object exists"
        if not response.json():
            assert False, "No response body"

    def test_get_collections_resource(self, creds, logger):
        logger.info("Test: Requesting Collections Resource")
        host, auth = creds

        api_root = host + "test-root/"
        collections_url = api_root + "collections/"

        response = requests.get(collections_url, auth=auth, verify=False)

        logger.info(response.status_code)
        if response.status_code != 200:
            assert False, "Collection does not exist"
        if not response.json():
            assert False, "No response body"
        json_body = response.json()

        assert len(json_body['collections']) > 0

    def test_get_collection(self, creds, logger):
        logger.info("Test: Requesting Collection")
        host, auth = creds

        api_root = host + "test-root/"
        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                response = requests.get(collection_url, auth=auth, verify=False)

                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Collection does not exist"
                if not response.json():
                    assert False, "No response body"

                json_body = response.json()

                assert json_body['alias'] == "test-collection-1"
                break
        else:
            assert False, "Collection not found"

    def test_get_read_only_collection(self, creds, logger):
        logger.info("Test: Requesting Collection")
        host, auth = creds

        api_root = host + "test-root/"
        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "read-only-collection":
                collection_url = api_root + f"collections/{collection.id}/"

                response = requests.get(collection_url, auth=auth, verify=False)

                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Collection does not exist"
                if not response.json():
                    assert False, "No response body"

                json_body = response.json()

                assert json_body['title'] == "read-only-collection"
                assert json_body['can_read'] == True
                assert json_body['can_write'] == False
                break
        else:
            assert False, "Collection does not exist"

    def test_get_write_only_collection(self, creds, logger):
        logger.info("Test: Requesting Collection")
        host, auth = creds

        api_root = host + "test-root/"
        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "write-only-collection":
                collection_url = api_root + f"collections/{collection.id}/"

                response = requests.get(collection_url, auth=auth, verify=False)

                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Collection does not exist"
                if not response.json():
                    assert False, "No response body"
                json_body = response.json()

                assert json_body['title'] == "write-only-collection"
                assert json_body['can_read'] == False
                assert json_body['can_write'] == True
                break
        else:
            assert False, "Collection does not exist"

    def test_get_no_read_write_collection(self, creds, logger):
        logger.info("Test: Requesting Collection")
        host, auth = creds

        api_root = host + "test-root/"
        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "no-read-write-collection":
                collection_url = api_root + f"collections/{collection.id}/"

                response = requests.get(collection_url, auth=auth, verify=False)

                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Collection does not exist"
                if not response.json():
                    assert False, "No response body"
                json_body = response.json()

                assert json_body['title'] == "no-read-write-collection"
                assert json_body['can_read'] == False
                assert json_body['can_write'] == False
                break
        else:
            assert False, "Collection does not exist"

    def test_get_collection_with_no_trailing_slash(self, creds, logger):
        logger.info("Test: Requesting Collection")
        host, auth = creds

        api_root = host + "test-root/"
        # If the forward slash is not provided, according to the TAXII specs, the collection is not returned
        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}"

                response = requests.get(collection_url, auth=auth, verify=False)

                if response.status_code != 403:
                    assert False, "Incorrect error code" + str(response.status_code)

                else:
                    assert True

    def test_get_non_existent_collection(self, creds, logger):
        logger.info("Test: Requesting Collection")
        host, auth = creds

        api_root = host + "test-root/"
        collection_url = api_root + "collections/foo/"

        response = requests.get(collection_url, auth=auth, verify=False)

        if response.status_code != 404:
            assert False, "Incorrect error code" + str(response.status_code)

        else:
            assert True

    def test_read_request_for_write_only_collection(self, creds, logger):
        logger.info("Test: Requesting Collection")
        host, auth = creds

        api_root = host + "test-root/"
        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "write-only-collection":
                collection_url = api_root + f"collections/{collection.id}"

                response = requests.get(collection_url, auth=auth, verify=False)
                logger.info(response.status_code)

                if response.status_code != 403:
                    assert False, "Collection is readable!"
                break
        else:
            assert False, "Collection does not exist"

    def test_write_request_for_read_only_collection(self, creds, bad_ip_test_data, bundle_data, logger):
        logger.info("Test: Check POST to read-only Collection Fails")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "read-only-collection":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add an object to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)

                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)

                objects = [bad_ip_test_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 403:
                    assert False, "Collection is Writeable!"
                break
        else:
            assert False, "Collection does not exist"

    def test_read_request_for_no_read_write_collection(self, creds, logger):
        logger.info("Test: Requesting Collection")
        host, auth = creds

        api_root = host + "test-root/"
        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "write-only-collection":
                collection_url = api_root + f"collections/{collection.id}/objects"

                response = requests.get(collection_url, auth=auth, verify=False)
                logger.info(response.status_code)

                if response.status_code != 403:
                    assert False, "Collection is readable!"
                break
        else:
            assert False, "Collection does not exist"

    def test_write_request_for_no_read_write_collection(self, creds, bad_ip_test_data, bundle_data, logger):

        logger.info("Test: Check POST to read-only Collection Fails")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "no-read-write-collection":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add an object to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)

                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)

                objects = [bad_ip_test_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 403:
                    assert False, "Collection is Writeable!"
                break

        else:
            assert False, "Collection does not exist"

    def test_delete_object_from_collection(self, creds, bad_ip_test_data, bundle_data, logger):
        logger.info("Test: Check DELETE Object from Collection Request")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add an object to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)

                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)

                objects = [bad_ip_test_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                time.sleep(5)

                #Find this object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Delete the new object from the collection
                object_url = collection_url + "/objects/" + object_uuid

                response = requests.delete(object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break

        else:
            assert False, "Collection does not exist"

    def test_add_indicator_pattern_collection(self, creds, bad_ip_test_data, bundle_data, logger):
        logger.info("Test: Add an Indicator Object with a pattern")
        host, auth = creds

        pattern = "[ipv4-addr:value = '198.51.100.1/32' OR ipv4-addr:value = '203.0.113.33/32' OR ipv6-addr:value = '2001:0db8:dead:beef:dead:beef:dead:0001/128'] REPEATS 5 TIMES"
        pattern_type = "stix"
        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add an object to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                bad_ip_test_data['id'] = object_uuid

                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                bad_ip_test_data['name'] = generate_random_string(5)
                bad_ip_test_data['pattern'] = pattern
                bad_ip_test_data['pattern_type'] = pattern_type

                objects = [bad_ip_test_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection with pattern "
                if not response.json():
                    assert False, "Missing response status with pattern "

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }
                time.sleep(5)
                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth,
                                        verify=False)

                assert response.json()['status'] == "complete", "Failed to publish object with pattern"

                #Find this object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object with pattern not found in the collection"

                # Delete the new object from the collection
                object_url = collection_url + object_uuid

                response = requests.delete(object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object with pattern "
            break

        else:
            assert False, "Collection does not exist"

    def test_get_all_objects_from_collection(self, creds, bad_ip_test_data, test_identity_data, bundle_data, logger):
        logger.info("Test: Check GET Objects from Collection Request")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                identity_uuid = "identity--" + str(uuid.uuid4())
                test_identity_data['id'] = identity_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                test_identity_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                test_identity_data['created'] = str(dt)
                test_identity_data['modified'] = str(dt)

                objects = [bad_ip_test_data, test_identity_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                time.sleep(5)

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the identity object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + identity_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert identity_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Get all objects from the collection
                response = requests.get(collection_url + 'objects/', headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) >= 2
                indicator_found = False
                identity_found = False
                for obj in response.json()['objects']:
                    if obj['id'] == object_uuid:
                        indicator_found = True
                    if obj['id'] == identity_uuid:
                        identity_found = True
                assert indicator_found, "Indicator not found in collection"
                assert identity_found, "Identity not found in collection"

                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                identity_object_url = collection_url + 'objects/' + identity_uuid
                response = requests.delete(identity_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Failed to create object"

    def test_get_all_collection_objects_empty_collection(self, creds, logger):
        logger.info("Test: Requesting Collection")
        host, auth = creds

        api_root = host + "test-root/"
        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "empty_collection":
                collection_url = api_root + f"collections/{collection.id}/"

                response = requests.get(collection_url + 'objects/', auth=auth, verify=False)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Collection does not exist"
                if not response.json():
                    assert True, "No response body"
                break
        else:
            assert False, "Collection does not exist"

    def test_get_non_existent_object(self, creds, logger):
        logger.info("Test: Requesting Non existing Object from Collection")
        host, auth = creds

        api_root = host + "test-root/"
        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/objects/sdj-099898"

                response = requests.get(collection_url, auth=auth, verify=False)

                logger.info(response.status_code)

                if response.status_code != 404:
                    assert False, "Incorrect error code" + str(response.status_code)

                else:
                    assert True
                break
        else:
            assert False, "Collection does not exist"

    def test_get_object_versions(self, creds, bad_ip_test_data, bundle_data, logger):
        logger.info("Test: Get Object versions")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add an object to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)

                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)

                objects = [bad_ip_test_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                time.sleep(5)

                # Find this object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Get Object versions
                obj_url = collection_url + "objects/" + object_uuid + "/versions/"
                response = requests.get(obj_url, headers=headers,
                                           verify=False, auth=auth)

                assert str(dt) in response.json()['versions']

                # Delete the new object from the collection
                object_url = api_root + "collections/fcd2c97e-20aa-4ed0-ac3a-cad8eafad093/objects/" + object_uuid

                response = requests.delete(object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_get_2_objects_from_collection_manifest(self, creds, bad_ip_test_data, test_identity_data,bundle_data, another_identity_data, logger):
        logger.info("Test: Check GET Objects from Collection Request")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                identity_uuid = "identity--" + str(uuid.uuid4())
                test_identity_data['id'] = identity_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                test_identity_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                test_identity_data['created'] = str(dt)
                test_identity_data['modified'] = str(dt)

                objects = [bad_ip_test_data, test_identity_data, another_identity_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                time.sleep(5)

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the identity object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + identity_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert identity_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find another identity object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + another_identity_data['id'], headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert another_identity_data['id'] == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Get 2 objects from the collection manifest
                response = requests.get(collection_url + 'manifest/?limit=2', headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) == 2
                assert response.json()['more'] == True

                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                identity_object_url = collection_url + 'objects/' + identity_uuid
                response = requests.delete(identity_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                another_identity_object_url = collection_url + 'objects/' + another_identity_data['id']
                response = requests.delete(another_identity_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_get_indicator_type_object_from_collection(self, creds, bad_ip_test_data, test_identity_data, bundle_data, logger):
        logger.info("Test: Check GET a particular type of Object from Collection Request")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                identity_uuid = "identity--" + str(uuid.uuid4())
                test_identity_data['id'] = identity_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                test_identity_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                test_identity_data['created'] = str(dt)
                test_identity_data['modified'] = str(dt)

                objects = [bad_ip_test_data, test_identity_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                time.sleep(5)

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the identity object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + identity_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert identity_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Get Indicator object from the collection
                response = requests.get(collection_url + 'objects/?match[type]=indicator', headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) >= 1
                for obj in response.json()['objects']:
                    assert obj['type'] == "indicator", "Found wrong object type"


                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                identity_object_url = collection_url + 'objects/' + identity_uuid
                response = requests.delete(identity_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_get_indicator_type_object_manifest_from_collection(self, creds, bad_ip_test_data, test_identity_data, bundle_data, logger):
        logger.info("Test: Check GET a particular type of Object from Collection Request")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                identity_uuid = "identity--" + str(uuid.uuid4())
                test_identity_data['id'] = identity_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                test_identity_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                test_identity_data['created'] = str(dt)
                test_identity_data['modified'] = str(dt)

                objects = [bad_ip_test_data, test_identity_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                time.sleep(5)

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the identity object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + identity_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert identity_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Get Indicator object manifest from the collection
                response = requests.get(collection_url + 'manifest/?match[type]=indicator', headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) >= 1
                for obj in response.json()['objects']:
                    assert "indicator--" in obj['id'], "Found wrong object type"


                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                identity_object_url = collection_url + 'objects/' + identity_uuid
                response = requests.delete(identity_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_get_object_last_version(self, creds, bad_ip_test_data, bundle_data, logger):
        logger.info("Test: Get Object versions")
        host, auth = creds

        api_root = host + "test-root/"

        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add an object to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)

                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)

                objects = [bad_ip_test_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                time.sleep(5)

                # Find this object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Get Object last version
                obj_url = collection_url + "objects/" + object_uuid + "/?match[version]=last"
                response = requests.get(obj_url, headers=headers,
                                           verify=False, auth=auth)

                assert bad_ip_test_data['type'] in response.json()['objects'][0]['type']
                assert object_uuid in response.json()['objects'][0]['id']
                assert str(dt) == response.json()['objects'][0]['created']

                # Delete the new object from the collection
                object_url = api_root + "collections/fcd2c97e-20aa-4ed0-ac3a-cad8eafad093/objects/" + object_uuid

                response = requests.delete(object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_get_object_of_specified_spec_version(self, creds, bad_ip_test_data, bundle_data, logger):
        logger.info("Test: Get Object versions")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add an object to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)

                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)

                objects = [bad_ip_test_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                time.sleep(5)

                # Find this object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Get Object of specified spec version
                obj_url = collection_url + "objects/?match[spec_version]=2.1"
                response = requests.get(obj_url, headers=headers,
                                           verify=False, auth=auth)

                for obj in response.json()['objects']:
                    assert obj['spec_version'] == "2.1"

                # Delete the new object from the collection
                object_url = api_root + "collections/fcd2c97e-20aa-4ed0-ac3a-cad8eafad093/objects/" + object_uuid

                response = requests.delete(object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_logical_or_operator(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, logger):
        logger.info("Test: Test Logical OR Operator")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)

                objects = [bad_ip_test_data, campaign_data, threat_actor_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)
                time.sleep(5)

                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Test OR logical operator
                response = requests.get(collection_url + 'objects/?match[type]=campaign, threat-actor', headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) >= 2

                for obj in response.json()['objects']:
                    assert obj['type'] in ['campaign', 'threat-actor']

                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_logical_and_operator(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, logger):
        logger.info("Test: Logical AND Operator")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)

                objects = [bad_ip_test_data, campaign_data, threat_actor_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                time.sleep(5)
                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"
                url = collection_url + 'objects/?match[type]=indicator&match[id]=' + object_uuid

                # Test AND logical operator
                response = requests.get(url, headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) == 1

                assert response.json()['objects'][0]['type'] == "indicator"
                assert response.json()['objects'][0]['id'] == object_uuid

                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_logical_or_and_operator(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, malware_data, logger):
        logger.info("Test: Logical AND Operator")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                malware_uuid = "malware--" + str(uuid.uuid4())
                malware_data['id'] = malware_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                malware_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)
                malware_data['created'] = str(dt)
                malware_data['modified'] = str(dt)

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, malware_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                time.sleep(5)
                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                #Find the Malware object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + malware_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert malware_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                url = collection_url + 'objects/?match[type]=campaign, malware&match[version]=first,last'

                # Test OR and AND logical operator
                response = requests.get(url, headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) >= 2

                for obj in response.json()['objects']:
                    assert obj['type'] in ['campaign', 'malware']


                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                malware_url = collection_url + 'objects/' + malware_uuid
                response = requests.delete(malware_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_duplicate_filters(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, malware_data, logger):
        logger.info("Test: Logical AND Operator")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                malware_uuid = "malware--" + str(uuid.uuid4())
                malware_data['id'] = malware_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                malware_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)
                malware_data['created'] = str(dt)
                malware_data['modified'] = str(dt)

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, malware_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                time.sleep(5)
                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Malware object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + malware_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert malware_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                url = collection_url + '/objects/?match[type]=campaign&match[type]=malware'

                # Test duplicate filters
                response = requests.get(url, headers=headers, verify=False, auth=auth)
                assert response.status_code == 400


                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                malware_url = collection_url + 'objects/' + malware_uuid
                response = requests.delete(malware_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_tier1_testcase(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, malware_data, logger):
        logger.info("Test: Tier1 Test case")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                malware_uuid = "malware--" + str(uuid.uuid4())
                malware_data['id'] = malware_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                malware_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)
                malware_data['created'] = str(dt)
                malware_data['modified'] = str(dt)

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, malware_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']
                time.sleep(5)
                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)


                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Malware object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + malware_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert malware_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                url = collection_url + 'objects/?match[confidence]=90,91,92,93,94'

                # Test Tier1 testcase
                response = requests.get(url, headers=headers, verify=False, auth=auth)
                assert response.status_code == 200

                for obj in response.json()['objects']:
                    assert obj['confidence'] in [90, 91, 92, 93, 94]


                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                malware_url = collection_url + 'objects/' + malware_uuid
                response = requests.delete(malware_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_tier2_testcase(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, malware_email_spam_data, malware_key_logger_data, logger):
        logger.info("Test: Tier1 Test case")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                malware1_uuid = "malware--" + str(uuid.uuid4())
                malware_email_spam_data['id'] = malware1_uuid
                malware2_uuid = "malware--" + str(uuid.uuid4())
                malware_key_logger_data['id'] = malware2_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                malware_email_spam_data['name'] = generate_random_string(5)
                malware_key_logger_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)
                malware_email_spam_data['created'] = str(dt)
                malware_email_spam_data['modified'] = str(dt)
                malware_key_logger_data['created'] = str(dt)
                malware_key_logger_data['modified'] = str(dt)

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, malware_key_logger_data, malware_email_spam_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }
                time.sleep(5)
                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Malware object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + malware1_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert malware1_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Malware object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + malware2_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert malware2_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                url = collection_url + 'objects/?match[capabilities]=emails-spam'

                # Test Tier2 testcase
                response = requests.get(url, headers=headers, verify=False, auth=auth)
                assert response.status_code == 200

                for obj in response.json()['objects']:
                    assert 'emails-spam' in obj['capabilities']


                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                malware_url = collection_url + 'objects/' + malware1_uuid
                response = requests.delete(malware_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                malware_url = collection_url + 'objects/' + malware2_uuid
                response = requests.delete(malware_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_tier3_testcase(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, malware_email_spam_data, process_data, logger):
        logger.info("Test: Tier3 Test case")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                malware1_uuid = "malware--" + str(uuid.uuid4())
                malware_email_spam_data['id'] = malware1_uuid
                process_uuid = "process--" + str(uuid.uuid4())
                process_data['id'] = process_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                malware_email_spam_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)
                malware_email_spam_data['created'] = str(dt)
                malware_email_spam_data['modified'] = str(dt)

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, process_data, malware_email_spam_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                time.sleep(5)

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"


                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Malware object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + malware1_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert malware1_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Process object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + process_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert process_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                url = collection_url + 'objects/?match[service_status]=SERVICE_STOPPED'

                # Test Tier3 testcase
                response = requests.get(url, headers=headers, verify=False, auth=auth)
                assert response.status_code == 200

                for obj in response.json()['objects']:
                    assert 'SERVICE_STOPPED' in obj['extensions']['windows-service-ext']['service_status']


                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                malware_url = collection_url + 'objects/' + malware1_uuid
                response = requests.delete(malware_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                malware_url = collection_url + 'objects/' + process_uuid
                response = requests.delete(malware_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_relationships_testcase(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, malware_email_spam_data, process_data, relationship_data, sighting_data, logger):
        logger.info("Test: Relationships Test case")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                malware1_uuid = "malware--" + str(uuid.uuid4())
                malware_email_spam_data['id'] = malware1_uuid
                process_uuid = "process--" + str(uuid.uuid4())
                sighting_uuid = "sighting--" + str(uuid.uuid4())
                relationship_uuid = "relationship--" + str(uuid.uuid4())
                process_data['id'] = process_uuid
                bad_ip_test_data['id'] = object_uuid
                sighting_data['id'] = sighting_uuid
                relationship_data['id'] = relationship_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                malware_email_spam_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)
                malware_email_spam_data['created'] = str(dt)
                malware_email_spam_data['modified'] = str(dt)
                sighting_data['created'] = str(dt)
                sighting_data['modified'] = str(dt)
                relationship_data['created'] = str(dt)
                relationship_data['modified'] = str(dt)
                sighting_data['sighting_of_ref'] = object_uuid
                sighting_data['count'] = 10
                relationship_data['relationship_type'] = "indicates"
                relationship_data['source_ref'] = object_uuid
                relationship_data['target_ref'] = malware1_uuid

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, process_data, malware_email_spam_data, relationship_data, sighting_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                time.sleep(5)

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"


                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Malware object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + malware1_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert malware1_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Process object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + process_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert process_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Relationship object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + relationship_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert relationship_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Sighting object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + sighting_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert sighting_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                url = collection_url + 'objects/?match[relationships-all]=' + object_uuid

                # Test Tier3 testcase
                response = requests.get(url, headers=headers, verify=False, auth=auth)
                assert response.status_code == 200

                for obj in response.json()['objects']:
                    if obj['type'] == 'relationship':
                        assert object_uuid == obj['source_ref']
                    elif obj['type'] == 'sighting':
                        assert object_uuid == obj['sighting_of_ref']


                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                malware_url = collection_url + 'objects/' + malware1_uuid
                response = requests.delete(malware_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                process_url = collection_url + 'objects/' + process_uuid
                response = requests.delete(process_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                relationship_url = collection_url + 'objects/' + relationship_uuid
                response = requests.delete(relationship_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                sighting_url = collection_url + 'objects/' + sighting_uuid
                response = requests.delete(sighting_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_calculation_testcase(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, malware_data, logger):
        logger.info("Test: Calculation Test case")
        host, auth = creds

        api_root = host + "test-root/"

        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                malware_uuid = "malware--" + str(uuid.uuid4())
                malware_data['id'] = malware_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                malware_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)
                malware_data['created'] = str(dt)
                malware_data['modified'] = str(dt)

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, malware_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }
                time.sleep(5)
                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Malware object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + malware_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert malware_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                url = collection_url + 'objects/?match[confidence-gte]=91'

                # Test Tier1 testcase
                response = requests.get(url, headers=headers, verify=False, auth=auth)
                assert response.status_code == 200

                for obj in response.json()['objects']:
                    assert obj['confidence'] == 91


                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                malware_url = collection_url + 'objects/' + malware_uuid
                response = requests.delete(malware_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_custom_property(self, creds, bad_ip_test_data, bundle_data, logger):
        logger.info("Test: Custom Property Test Case")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add an object to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)

                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)

                objects = [bad_ip_test_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects
                bundle_data['x_18467e42_04f4_4505_93c8_9f1cf29e1045_test_client'] = "The Client sends the Server a custom property."

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }
                time.sleep(5)
                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)

                assert response.json()['status'] == "complete"

                #Find this object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Delete the new object from the collection
                object_url = api_root + "collections/fcd2c97e-20aa-4ed0-ac3a-cad8eafad093/objects/" + object_uuid

                response = requests.delete(object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_match_country(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, logger):
        logger.info("Test: Test Match Country")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)

                location_data = read_json_data_from_file("test_data/location.json")
                location_data['id'] = "location--" + str(uuid.uuid4())

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, location_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)
                time.sleep(5)

                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Location object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + location_data['id'], headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert location_data['id'] == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Test OR logical operator
                response = requests.get(collection_url + 'objects/?match[country]=CN', headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) >= 1

                for obj in response.json()['objects']:
                    assert obj['type'] == 'location'

                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                location_object_url = collection_url + 'objects/' + location_data['id']
                response = requests.delete(location_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_match_administrative_area(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, logger):
        logger.info("Test: Test Match Administrative Area")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)

                location_data = read_json_data_from_file("test_data/location.json")
                location_data['id'] = "location--" + str(uuid.uuid4())

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, location_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)
                time.sleep(5)

                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Location object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + location_data['id'], headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert location_data['id'] == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Test OR logical operator
                response = requests.get(collection_url + 'objects/?match[administrative_area]=CN-SH', headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) >= 1

                for obj in response.json()['objects']:
                    assert obj['type'] == 'location'

                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                location_object_url = collection_url + 'objects/' + location_data['id']
                response = requests.delete(location_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"

    def test_match_administrative_area_virginia(self, creds, bad_ip_test_data, campaign_data, bundle_data, threat_actor_data, logger):
        logger.info("Test: Test Match Administrative Area")
        host, auth = creds

        api_root = host + "test-root/"
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }

        api_root_obj = ApiRoot(api_root, auth=auth, verify=False)
        for collection in api_root_obj.collections:
            if collection.title == "test-collection-1":
                collection_url = api_root + f"collections/{collection.id}/"

                # Add objects to this collection
                new_uuid = uuid.uuid4()
                object_uuid = "indicator--" + str(new_uuid)
                bundle_uuid = "bundle--" + str(uuid.uuid4())
                campaign_uuid = "campaign--" + str(uuid.uuid4())
                campaign_data['id'] = campaign_uuid
                threat_actor_uuid = "threat-actor--" + str(uuid.uuid4())
                threat_actor_data['id'] = threat_actor_uuid
                bad_ip_test_data['id'] = object_uuid
                bad_ip_test_data['name'] = generate_random_string(5)
                campaign_data['name'] = generate_random_string(5)
                threat_actor_data['name'] = generate_random_string(5)
                dt = datetime.now(timezone.utc)
                dt = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                bad_ip_test_data['created'] = str(dt)
                bad_ip_test_data['modified'] = str(dt)
                bad_ip_test_data['valid_from'] = str(dt)
                campaign_data['created'] = str(dt)
                campaign_data['modified'] = str(dt)
                threat_actor_data['created'] = str(dt)
                threat_actor_data['modified'] = str(dt)

                location_data = read_json_data_from_file("test_data/location.json")
                location_data['id'] = "location--" + str(uuid.uuid4())
                location_data['country'] = 'US'
                location_data['administrative_area'] = 'US-VA'
                location_data['name'] = 'Virginia'
                location_data['region'] = 'Northern-America'

                objects = [bad_ip_test_data, campaign_data, threat_actor_data, location_data]

                bundle_data["id"] = bundle_uuid
                bundle_data["objects"] = objects

                response = requests.post(collection_url + 'objects/', headers=headers, data=json.dumps(bundle_data),
                                         verify=False, auth=auth)

                if response.status_code != 202:
                    assert False, "Error adding an Object to the Collection"
                if not response.json():
                    assert False, "Missing response status"

                status_id = response.json()['id']

                headers = {
                    'Accept': 'application/taxii+json;version=2.1',
                }

                response = requests.get(collection_url + "status/" + status_id + "/", headers=headers, auth=auth, verify=False)
                time.sleep(5)

                assert response.json()['status'] == "complete"

                #Find the indicator object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + object_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert object_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the campaign object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + campaign_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert campaign_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Threat Actor object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + threat_actor_uuid, headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert threat_actor_uuid == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Find the Location object manifest in the collection
                response = requests.get(collection_url + "manifest/?match[id]=" + location_data['id'], headers=headers,
                                        verify=False, auth=auth)
                logger.info(response.status_code)

                if response.status_code != 200:
                    assert False, "Incorrect error code" + str(response.status_code)

                logger.info(response.json())

                assert location_data['id'] == response.json()['objects'][0]['id'], "Object not found in the collection"

                # Test OR logical operator
                response = requests.get(collection_url + 'objects/?match[administrative_area]=US-VA&match[country]=US', headers=headers, verify=False, auth=auth)

                assert len(response.json()['objects']) >= 1

                for obj in response.json()['objects']:
                    assert obj['type'] == 'location'

                # Delete the new objects from the collection
                indicator_object_url = collection_url + 'objects/' + object_uuid

                response = requests.delete(indicator_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                campaign_object_url = collection_url + 'objects/' + campaign_uuid
                response = requests.delete(campaign_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                threat_actor_object_url = collection_url + 'objects/' + threat_actor_uuid
                response = requests.delete(threat_actor_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"

                location_object_url = collection_url + 'objects/' + location_data['id']
                response = requests.delete(location_object_url, headers=headers,
                                           verify=False, auth=auth)

                assert response.status_code == 200, "Failed to delete object"
            break
        else:
            assert False, "Collection does not exist"


