//! Neo4j graph database connector.
//!
//! # Read-only protection
//!
//! This connector does not parse or validate Cypher queries. Write protection
//! relies on Neo4j database-level permissions: configure the connector
//! credentials with a user that has the built-in `reader` role
//! (requires Neo4j Enterprise Edition). Community Edition does not support
//! role-based access control, so all authenticated users have full access.
//!
//! # SSL / TLS
//!
//! Encryption is selected by the `NEO4J_URI` scheme:
//!
//! * `neo4j://`     — plaintext, no TLS
//! * `neo4j+s://`   — TLS with server-certificate verification
//! * `neo4j+ssc://` — TLS without verification (self-signed certificates)
//!
//! To trust a private/custom CA with `neo4j+s`, provide the CA certificate
//! PEM file path through the `NEO4J_CA_CERT` credential. The connector
//! adds it to the certificate trust store used to validate the Neo4j server.
//!
//! # Schema inference
//!
//! Schema is inferred by executing the query and inspecting the first row's
//! field types. If the query returns no rows, an empty schema (0 columns) is
//! returned — Neo4j has no metadata API to discover column definitions without
//! executing the query.

pub mod connector;
mod types;

pub use connector::{Neo4jConnector, Neo4jReader};
