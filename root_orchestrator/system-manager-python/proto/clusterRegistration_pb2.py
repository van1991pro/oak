# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: clusterRegistration.proto
# Protobuf Python Version: 4.25.0
"""Generated protocol buffer code."""

from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x19\x63lusterRegistration.proto\x12\x13\x63lusterRegistration"+\n\nCS1Message\x12\x1d\n\x15hello_service_manager\x18\x01 \x01(\t"+\n\nSC1Message\x12\x1d\n\x15hello_cluster_manager\x18\x01 \x01(\t"\xa7\x01\n\nCS2Message\x12\x14\n\x0cmanager_port\x18\x01 \x01(\x05\x12\x1e\n\x16network_component_port\x18\x02 \x01(\x05\x12\x14\n\x0c\x63luster_name\x18\x03 \x01(\t\x12\x33\n\x0c\x63luster_info\x18\x04 \x03(\x0b\x32\x1d.clusterRegistration.KeyValue\x12\x18\n\x10\x63luster_location\x18\x05 \x01(\t"&\n\x08KeyValue\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t"\x18\n\nSC2Message\x12\n\n\x02id\x18\x01 \x01(\t2\xc7\x01\n\x10register_cluster\x12Z\n\x14handle_init_greeting\x12\x1f.clusterRegistration.CS1Message\x1a\x1f.clusterRegistration.SC1Message"\x00\x12W\n\x11handle_init_final\x12\x1f.clusterRegistration.CS2Message\x1a\x1f.clusterRegistration.SC2Message"\x00\x62\x06proto3'  # noqa: E501
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "clusterRegistration_pb2", _globals)
if _descriptor._USE_C_DESCRIPTORS is False:
    DESCRIPTOR._options = None
    _globals["_CS1MESSAGE"]._serialized_start = 50
    _globals["_CS1MESSAGE"]._serialized_end = 93
    _globals["_SC1MESSAGE"]._serialized_start = 95
    _globals["_SC1MESSAGE"]._serialized_end = 138
    _globals["_CS2MESSAGE"]._serialized_start = 141
    _globals["_CS2MESSAGE"]._serialized_end = 308
    _globals["_KEYVALUE"]._serialized_start = 310
    _globals["_KEYVALUE"]._serialized_end = 348
    _globals["_SC2MESSAGE"]._serialized_start = 350
    _globals["_SC2MESSAGE"]._serialized_end = 374
    _globals["_REGISTER_CLUSTER"]._serialized_start = 377
    _globals["_REGISTER_CLUSTER"]._serialized_end = 576
# @@protoc_insertion_point(module_scope)
