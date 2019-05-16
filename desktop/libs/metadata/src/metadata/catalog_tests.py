#!/usr/bin/env python
# -- coding: utf-8 --
# Licensed to Cloudera, Inc. under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  Cloudera, Inc. licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import json

from nose.plugins.skip import SkipTest
from nose.tools import assert_equal, assert_true

from django.contrib.auth.models import User
from django.urls import reverse

from desktop.auth.backend import rewrite_user
from desktop.lib.django_test_util import make_logged_in_client
from desktop.lib.test_utils import add_to_group, grant_access
from hadoop.pseudo_hdfs4 import is_live_cluster

from metadata import conf
from metadata.conf import has_catalog, NAVIGATOR, ATLAS, get_navigator_auth_password, get_navigator_auth_username
from metadata.catalog_api import _augment_highlighting
from metadata.catalog.navigator_client import NavigatorApi
from metadata.catalog.atlas_client import AtlasApi


LOG = logging.getLogger(__name__)


class TestNavigator(object):

  @classmethod
  def setup_class(cls):
    cls.client = make_logged_in_client(username='test', is_superuser=False)
    cls.user = User.objects.get(username='test')
    cls.user = rewrite_user(cls.user)
    add_to_group('test')
    grant_access("test", "test", "metadata")

    if not is_live_cluster() or not has_catalog(cls.user):
      raise SkipTest

    cls.api = NavigatorApi(cls.user)


  @classmethod
  def teardown_class(cls):
    cls.user.is_superuser = False
    cls.user.save()


  def test_search_entities_view(self):
    resp = self.client.post(reverse('metadata:search_entities'), {'query_s': json.dumps('châteaux'), 'limit': 25, 'sources': json.dumps(['sql'])})
    json_resp = json.loads(resp.content)
    assert_equal(0, json_resp['status'], json_resp)


  def test_search_entities_interactive_view(self):
    resp = self.client.post(reverse('metadata:search_entities_interactive'), {'query_s': json.dumps('châteaux'), 'limit': 10, 'sources': json.dumps(['sql'])})
    json_resp = json.loads(resp.content)
    assert_equal(0, json_resp['status'], json_resp)


  def test_find_entity(self):
    # Disabled as entities not showing up in time
    raise SkipTest

    entity = self.api.find_entity(source_type='HIVE', type='DATABASE', name='default')
    assert_true('identity' in entity, entity)


  def test_api_find_entity(self):
    # Disabled as entities not showing up in time
    raise SkipTest

    resp = self.client.get(reverse('metadata:find_entity'), {'type': 'database', 'name': 'default'})
    json_resp = json.loads(resp.content)
    assert_equal(0, json_resp['status'])
    assert_true('entity' in json_resp, json_resp)
    assert_true('identity' in json_resp['entity'], json_resp)


  def test_api_tags(self):
    # Disabled as entities not showing up in time
    raise SkipTest

    entity = self.api.find_entity(source_type='HIVE', type='DATABASE', name='default')
    entity_id = entity['identity']
    tags = entity['tags'] or []

    resp = self.client.post(reverse('metadata:add_tags'), self._format_json_body({'id': entity_id}))
    json_resp = json.loads(resp.content)
    # add_tags requires a list of tags
    assert_equal(-1, json_resp['status'])

    resp = self.client.post(reverse('metadata:add_tags'), self._format_json_body({'id': entity_id, 'tags': ['hue_test']}))
    json_resp = json.loads(resp.content)
    assert_equal(0, json_resp['status'], json_resp)
    assert_equal(set(tags + ['hue_test']), set(json_resp['entity']['tags']))

    resp = self.client.post(reverse('metadata:delete_tags'), self._format_json_body({'id': entity_id, 'tags': ['hue_test']}))
    json_resp = json.loads(resp.content)
    assert_equal(0, json_resp['status'], json_resp)
    assert_true(tags, json_resp['entity']['tags'])


  def test_api_properties(self):
    # Disabled as entities not showing up in time
    raise SkipTest

    entity = self.api.find_entity(source_type='HIVE', type='DATABASE', name='default')
    entity_id = entity['identity']
    props = entity['properties'] or {}

    resp = self.client.post(reverse('metadata:update_properties'), self._format_json_body({'id': entity_id, 'properties': {'hue': 'test'}}))
    json_resp = json.loads(resp.content)
    assert_equal(0, json_resp['status'], json_resp)
    props.update({'hue': 'test'})
    assert_equal(props, json_resp['entity']['properties'])

    resp = self.client.post(reverse('metadata:delete_metadata_properties'), self._format_json_body({'id': entity_id, 'keys': ['hue']}))
    json_resp = json.loads(resp.content)
    assert_equal(0, json_resp['status'], json_resp)
    del props['hue']
    assert_equal(entity['properties'], json_resp['entity']['properties'])


  def test_search_entities_interactive(self):
    resp = self.client.post(reverse('metadata:list_tags'), self._format_json_body({'prefix': 'hue'}))
    json_resp = json.loads(resp.content)
    assert_true('tags' in json_resp)
    assert_equal(0, json_resp['status'], json_resp)


  def test_suggest(self):
    resp = self.client.post(reverse('metadata:suggest'), self._format_json_body({'prefix': 'hue'}))
    json_resp = json.loads(resp.content)
    assert_true('suggest' in json_resp)
    assert_equal(0, json_resp['status'], json_resp)


  def test_lineage(self):
    # TODO: write me
    pass


  def _format_json_body(self, post_dict):
    json_dict = {}
    for key, value in post_dict.items():
      json_dict[key] = json.dumps(value)
    return json_dict


class TestNavigatorAPI(object):

  def test_augment_highlighting_emty_db_name(self):
    query_s = 'type:database*'
    records = [
      {u'customProperties': None, u'deleteTime': None, u'fileSystemPath': u'hdfs://Enchilada/data/marketsriskcalc/work/hive', u'description': None, u'params': None, u'type': u'DATABASE', u'internalType': u'hv_database', u'sourceType': u'HIVE', u'tags': None, u'deleted': False, u'technicalProperties': None, u'userEntity': False, u'originalDescription': None, u'metaClassName': u'hv_database', u'properties': None, u'identity': u'51002517', u'firstClassParentId': None, u'name': None, u'extractorRunId': u'845beb21b95783c4f55276a4ae38a332##3', u'sourceId': u'56850544', u'packageName': u'nav', u'parentPath': None, u'originalName': u'marketsriskcalc_work'}, {u'customProperties': None, u'deleteTime': None, u'fileSystemPath': u'hdfs://Enchilada/data/catssolprn/work/hive', u'description': None, u'params': None, u'type': u'DATABASE', u'internalType': u'hv_database', u'sourceType': u'HIVE', u'tags': None, u'deleted': False, u'technicalProperties': None, u'userEntity': False, u'originalDescription': None, u'metaClassName': u'hv_database', u'properties': None, u'identity': u'51188932', u'firstClassParentId': None, u'name': None, u'extractorRunId': u'845beb21b95783c4f55276a4ae38a332##3', u'sourceId': u'56850544', u'packageName': u'nav', u'parentPath': None, u'originalName': u'catssolprn_work'}
    ]

    _augment_highlighting(query_s, records)
    assert_equal('', records[0]['parentPath'])

  def test_navigator_conf(self):
    resets = [
      NAVIGATOR.AUTH_CM_USERNAME.set_for_testing('cm_username'),
      NAVIGATOR.AUTH_CM_PASSWORD.set_for_testing('cm_pwd'),
      NAVIGATOR.AUTH_LDAP_USERNAME.set_for_testing('ldap_username'),
      NAVIGATOR.AUTH_LDAP_PASSWORD.set_for_testing('ldap_pwd'),
      NAVIGATOR.AUTH_SAML_USERNAME.set_for_testing('saml_username'),
      NAVIGATOR.AUTH_SAML_PASSWORD.set_for_testing('saml_pwd'),
    ]

    reset = NAVIGATOR.AUTH_TYPE.set_for_testing('CMDB')
    conf.NAVIGATOR_AUTH_PASSWORD = None

    try:
      assert_equal('cm_username', get_navigator_auth_username())
      assert_equal('cm_pwd', get_navigator_auth_password())

      reset()
      conf.NAVIGATOR_AUTH_PASSWORD = None
      reset = NAVIGATOR.AUTH_TYPE.set_for_testing('ldap')

      assert_equal('ldap_username', get_navigator_auth_username())
      assert_equal('ldap_pwd', get_navigator_auth_password())

      reset()
      conf.NAVIGATOR_AUTH_PASSWORD = None
      reset = NAVIGATOR.AUTH_TYPE.set_for_testing('SAML')

      assert_equal('saml_username', get_navigator_auth_username())
      assert_equal('saml_pwd', get_navigator_auth_password())
    finally:
      reset()
      conf.NAVIGATOR_AUTH_PASSWORD = None
      for _reset in resets:
        _reset()

class TestAtlas(object):

  @classmethod
  def setup_class(cls):
    cls.client = make_logged_in_client(username='test', is_superuser=False)
    cls.user = User.objects.get(username='test')
    cls.interface = 'atlas'
    cls.user = rewrite_user(cls.user)
    #cls.interface = self.request.POST.get('interface', CATALOG.INTERFACE.get())
    add_to_group('test')
    grant_access("test", "test", "metadata")

    if not is_live_cluster() or not has_catalog(cls.user):
      raise SkipTest

    cls.api = AtlasApi(cls.user)


  @classmethod
  def teardown_class(cls):
    cls.user.is_superuser = False
    cls.user.save()


  # def test_search_entities_view(self):
  #   resp = self.client.post(reverse('metadata:search_entities'), {'query_s': json.dumps('châteaux'), 'limit': 25, 'sources': json.dumps(['sql'])})
  #   json_resp = json.loads(resp.content)
  #   assert_equal(0, json_resp['status'], json_resp)
  #
  #
  # def test_search_entities_interactive_view(self):
  #   resp = self.client.post(reverse('metadata:search_entities_interactive'), {'query_s': json.dumps('châteaux'), 'limit': 10, 'sources': json.dumps(['sql'])})
  #   json_resp = json.loads(resp.content)
  #   assert_equal(0, json_resp['status'], json_resp)
  #
  #
  # def test_find_entity(self):
  #   # Disabled as entities not showing up in time
  #   raise SkipTest
  #
  #   entity = self.api.find_entity(source_type='HIVE', type='DATABASE', name='default')
  #   assert_true('identity' in entity, entity)

  # def test_api_get_entity_by_query_with_type_fs_path_and_name(self, typeName='fs_path', entityId='fs_path_tivoj_4'):
  #   # typeName = 'fs_path'
  #   query = '+'.join([typeName, 'where', 'name=']) + entityId
  #   expected_query = ' '.join([typeName, 'where', 'name=']) + entityId
  #   resp = self.client.get(reverse('metadata:catalog_get_entity'), {'query': query})
  #   json_resp = json.loads(resp.content)
  #   LOG.info("Hue response: %s", json_resp)
  #   assert_equal(0, json_resp['status'], json_resp)
  #   assert_equal(expected_query, json_resp['entities']['queryText'])

  def test_api_get_entity_by_query_with_type_hive_db_and_name(self, typeName='hive_db', name='sys'):
    # typeName = 'fs_path'
    query = '+'.join([typeName, 'where', 'name=']) + name
    expected_query = ' '.join([typeName, 'where', 'name=']) + name
    resp = self.client.get(reverse('metadata:catalog_get_entity'), {'query': query})
    json_resp = json.loads(resp.content)
    LOG.info("Hue response: %s", json_resp)
    assert_equal(0, json_resp['status'], json_resp)
    assert_equal(expected_query, json_resp['entities']['queryText'])

  def test_api_get_entity_guid_with_type_hive_db_and_name(self, typeName='hive_db', name='sys'):
    '''
    # query = "hive_db+where+name=sys+select+name,__guid"
    # query = hive_db + where + name = sys + select + qualifiedName, name, __guid
    # query=hdfs_path+select+name,__guid+limit+1
    {"queryType":"DSL","queryText":"hive_db where name=sys select name,__guid","attributes":{"name":["name","__guid"],"values":[["sys","16cab673-e4b1-4ee6-83cf-c0017ed855ca"]]}}
    '''

    query = "+".join([typeName, "where", "name=%s","select", "name,__guid", "limit", "1"]) %name

    # expected_query = ' '.join([typeName, 'where', 'name=']) + name
    expected_query = " ".join([typeName, "where", "name=%s","select", "name,__guid", "limit", "1"]) %name

    resp = self.client.get(reverse('metadata:catalog_get_entity'), {'query': query})
    json_resp = json.loads(resp.content)
    LOG.info("Hue response: %s", json_resp)
    assert_equal(0, json_resp['status'], json_resp)
    LOG.info(json_resp['entities']['queryText'])
    val = json_resp['entities']['attributes']['values']
    LOG.info(val[0][1])
    assert_equal(expected_query, json_resp['entities']['queryText'])
    assert_equal('79b3105a-659c-4a63-a4db-682a5a2b68e5', val[0][1])


  def test_api_get_entity_by_query_with_guid(self, guid='79b3105a-659c-4a63-a4db-682a5a2b68e5'):
    typeName = 'hive_db'
    query = '+'.join([typeName, 'where', '__guid="']) + guid + '"'
    expected_query = ' '.join([typeName, 'where', '__guid="']) + guid + '"'
    resp = self.client.get(reverse('metadata:catalog_get_entity'), {'query': query})
    json_resp = json.loads(resp.content)
    LOG.info("Hue response: %s", json_resp)
    assert_equal(0, json_resp['status'], json_resp)
    assert_equal(expected_query, json_resp['entities']['queryText'])
    # assert_equal(guid, json_resp['entities']['entities']['guid'])



  # def test_api_find_entity(self):
  #   # Disabled as entities not showing up in time
  #   # raise SkipTest
  # #     #
  # #     # resp = self.client.get(reverse('metadata:find_entity'), {'type': 'database', 'name': 'default'})
  # #     # json_resp = json.loads(resp.content)
  # #     # assert_equal(0, json_resp['status'])
  # #     # assert_true('entity' in json_resp, json_resp)
  # #     # assert_true('identity' in json_resp['entity'], json_resp)
  # #   query_data = {"excludeDeletedEntities": True,
  # #                 "includeSubClassifications": True,
  # #                 "includeSubTypes": True, "includeClassificationAttributes": True,
  # #                 "entityFilters": None, "tagFilters": None, "attributes": [],
  # #                 "query": "sys", "limit": 25, "offset": 0, "typeName": "hive_db", "classification": None,
  # #                 "termName": None}
  #   typeName = 'fs_path'
  #   entityId = 'fs_path_tivoj_4'
  #   query = typeName + '+where+name='+ entityId
  #   expected_query_str = typeName + " where name=" + entityId
  #   r = reverse('metadata:catalog_get_entity')
  #   resp = self.client.get(r, {'interface':'atlas'})
  #   json_resp = json.loads(resp.content)
  #   LOG.info("Atlas response: %s", json_resp)
  #
  #   LOG.info(resp['entities'])
  #   assert_equal(0, json_resp['status'], json_resp)
  #
  #   assert_equal(expected_query_str, json_resp['entities']['queryText'])
  #
  #
  # def test_api_tags(self):
  #   # Disabled as entities not showing up in time
  #   raise SkipTest
  #
  #   entity = self.api.find_entity(source_type='HIVE', type='DATABASE', name='default')
  #   entity_id = entity['identity']
  #   tags = entity['tags'] or []
  #
  #   resp = self.client.post(reverse('metadata:add_tags'), self._format_json_body({'id': entity_id}))
  #   json_resp = json.loads(resp.content)
  #   # add_tags requires a list of tags
  #   assert_equal(-1, json_resp['status'])
  #
  #   resp = self.client.post(reverse('metadata:add_tags'), self._format_json_body({'id': entity_id, 'tags': ['hue_test']}))
  #   json_resp = json.loads(resp.content)
  #   assert_equal(0, json_resp['status'], json_resp)
  #   assert_equal(set(tags + ['hue_test']), set(json_resp['entity']['tags']))
  #
  #   resp = self.client.post(reverse('metadata:delete_tags'), self._format_json_body({'id': entity_id, 'tags': ['hue_test']}))
  #   json_resp = json.loads(resp.content)
  #   assert_equal(0, json_resp['status'], json_resp)
  #   assert_true(tags, json_resp['entity']['tags'])
  #
  #
  # def test_api_properties(self):
  #   # Disabled as entities not showing up in time
  #   raise SkipTest
  #
  #   entity = self.api.find_entity(source_type='HIVE', type='DATABASE', name='default')
  #   entity_id = entity['identity']
  #   props = entity['properties'] or {}
  #
  #   resp = self.client.post(reverse('metadata:update_properties'), self._format_json_body({'id': entity_id, 'properties': {'hue': 'test'}}))
  #   json_resp = json.loads(resp.content)
  #   assert_equal(0, json_resp['status'], json_resp)
  #   props.update({'hue': 'test'})
  #   assert_equal(props, json_resp['entity']['properties'])
  #
  #   resp = self.client.post(reverse('metadata:delete_metadata_properties'), self._format_json_body({'id': entity_id, 'keys': ['hue']}))
  #   json_resp = json.loads(resp.content)
  #   assert_equal(0, json_resp['status'], json_resp)
  #   del props['hue']
  #   assert_equal(entity['properties'], json_resp['entity']['properties'])
  #
  #
  # def test_search_entities_interactive(self):
  #   resp = self.client.post(reverse('metadata:list_tags'), self._format_json_body({'prefix': 'hue'}))
  #   json_resp = json.loads(resp.content)
  #   assert_true('tags' in json_resp)
  #   assert_equal(0, json_resp['status'], json_resp)
  #
  #
  # def test_suggest(self):
  #   resp = self.client.post(reverse('metadata:suggest'), self._format_json_body({'prefix': 'hue'}))
  #   json_resp = json.loads(resp.content)
  #   assert_true('suggest' in json_resp)
  #   assert_equal(0, json_resp['status'], json_resp)

  # def test_atlas_conf(self):
  #   #get_catalog_auth_password
  #   resets = [
  #     CATALOG.AUTH_CM_USERNAME.set_for_testing('cm_username'),
  #     CATALOG.AUTH_CM_PASSWORD.set_for_testing('cm_pwd'),
  #     # CATALOG.AUTH_LDAP_USERNAME.set_for_testing('ldap_username'),
  #     # CATALOG.AUTH_LDAP_PASSWORD.set_for_testing('ldap_pwd'),
  #     # CATALOG.AUTH_SAML_USERNAME.set_for_testing('saml_username'),
  #     # CATALOG.AUTH_SAML_PASSWORD.set_for_testing('saml_pwd'),
  #   ]
  #
  #   reset = NAVIGATOR.AUTH_TYPE.set_for_testing('CMDB')
  #   conf.NAVIGATOR_AUTH_PASSWORD = None
  #
  #   try:
  #     assert_equal('cm_username', get_navigator_auth_username())
  #     assert_equal('cm_pwd', get_navigator_auth_password())
  #
  #     reset()
  #     conf.NAVIGATOR_AUTH_PASSWORD = None
  #     reset = NAVIGATOR.AUTH_TYPE.set_for_testing('ldap')
  #
  #     assert_equal('ldap_username', get_navigator_auth_username())
  #     assert_equal('ldap_pwd', get_navigator_auth_password())
  #
  #     reset()
  #     conf.NAVIGATOR_AUTH_PASSWORD = None
  #     reset = NAVIGATOR.AUTH_TYPE.set_for_testing('SAML')
  #
  #     assert_equal('saml_username', get_navigator_auth_username())
  #     assert_equal('saml_pwd', get_navigator_auth_password())
  #   finally:
  #     reset()
  #     conf.NAVIGATOR_AUTH_PASSWORD = None
  #     for _reset in resets:
  #       _reset()


  def test_lineage(self):
    # TODO: write me
    pass


  def _format_json_body(self, post_dict):
    json_dict = {}
    for key, value in post_dict.items():
      json_dict[key] = json.dumps(value)
    return json_dict
