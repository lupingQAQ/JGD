"""SQLite schema for the derived bytecode index."""
from __future__ import annotations

INDEX_VERSION = "jgd.bytecode-index/v1"

DDL = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jars (
  id INTEGER PRIMARY KEY,
  sha256 TEXT NOT NULL,
  path TEXT NOT NULL UNIQUE,
  size INTEGER NOT NULL,
  mtime_ns INTEGER NOT NULL,
  coordinates TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_jars_sha ON jars(sha256);

CREATE TABLE IF NOT EXISTS classes (
  id INTEGER PRIMARY KEY,
  jar_id INTEGER NOT NULL REFERENCES jars(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  super TEXT,
  access INTEGER NOT NULL DEFAULT 0,
  major INTEGER NOT NULL DEFAULT 0,
  interfaces_json TEXT NOT NULL DEFAULT '[]',
  origin TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_classes_name ON classes(name);
CREATE INDEX IF NOT EXISTS idx_classes_jar ON classes(jar_id);

CREATE TABLE IF NOT EXISTS methods (
  id INTEGER PRIMARY KEY,
  class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  desc TEXT NOT NULL,
  access INTEGER NOT NULL DEFAULT 0,
  code_size INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_methods_class ON methods(class_id);
CREATE INDEX IF NOT EXISTS idx_methods_name ON methods(name);

CREATE TABLE IF NOT EXISTS fields (
  id INTEGER PRIMARY KEY,
  class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  desc TEXT NOT NULL,
  access INTEGER NOT NULL DEFAULT 0,
  transient INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_fields_class ON fields(class_id);

CREATE TABLE IF NOT EXISTS invokes (
  id INTEGER PRIMARY KEY,
  caller_method_id INTEGER NOT NULL REFERENCES methods(id) ON DELETE CASCADE,
  callee_owner TEXT NOT NULL,
  callee_name TEXT NOT NULL,
  callee_desc TEXT NOT NULL,
  opcode TEXT NOT NULL,
  line INTEGER
);
CREATE INDEX IF NOT EXISTS idx_invokes_callee ON invokes(callee_owner, callee_name);
CREATE INDEX IF NOT EXISTS idx_invokes_caller ON invokes(caller_method_id);

CREATE TABLE IF NOT EXISTS field_access (
  id INTEGER PRIMARY KEY,
  method_id INTEGER NOT NULL REFERENCES methods(id) ON DELETE CASCADE,
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  desc TEXT NOT NULL,
  kind TEXT NOT NULL,
  opcode TEXT NOT NULL,
  line INTEGER
);
CREATE INDEX IF NOT EXISTS idx_field_access_method ON field_access(method_id);
CREATE INDEX IF NOT EXISTS idx_field_access_field ON field_access(owner, name);

CREATE TABLE IF NOT EXISTS strings (
  id INTEGER PRIMARY KEY,
  method_id INTEGER NOT NULL REFERENCES methods(id) ON DELETE CASCADE,
  value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_strings_method ON strings(method_id);
"""
