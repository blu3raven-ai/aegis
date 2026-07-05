"""Shared kernel for connector-style integrations.

Imported once at app startup to populate the registry. Domain folders
(notifications/, integrations/, runner/) register their connector classes
here via @register_connector.
"""
