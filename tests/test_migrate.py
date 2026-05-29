import pytest
import os
from src.migrate import _get_sqlite_schema, _translate_schema, TABLES_TO_MIGRATE


def test_tables_list():
    assert "analyses" in TABLES_TO_MIGRATE
    assert "users" in TABLES_TO_MIGRATE
    assert len(TABLES_TO_MIGRATE) > 10


def test_get_sqlite_schema():
    schema = _get_sqlite_schema("analyses")
    assert schema is not None
    assert "CREATE TABLE" in schema


def test_translate_schema():
    sqlite_sql = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, score REAL)"
    pg_sql = _translate_schema(sqlite_sql)
    assert "AUTOINCREMENT" not in pg_sql
    assert "IF NOT EXISTS" in pg_sql
    assert "DOUBLE PRECISION" in pg_sql
    assert "INTEGER" in pg_sql


def test_missing_table():
    schema = _get_sqlite_schema("nonexistent_table_xyz")
    assert schema is None
