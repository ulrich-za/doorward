# doorward-postgres

PostgreSQL storage for [doorward](https://crates.io/crates/doorward), the
headless sign-in library, through sqlx 0.9.

```rust,ignore
let pool = sqlx::PgPool::connect("postgres://app@localhost/app").await?;
let dw = doorward::Doorward::builder(doorward_postgres::PostgresStore::new(pool))
    .address(doorward::Address::new("https://repairs.example")?)
    .build()
    .await?;
```

- doorward's tables are prefixed `auth_` and upgraded by doorward under an
  advisory lock, so several copies of the app can start at once.
- `auth_users(id)` is a `uuid` the app can reference from its own tables.
- The pool is the app's: it chooses TLS and connection limits. doorward adds
  no TLS backend.
- Every query is a string literal with bound values.

Tests need a server: set `DOORWARD_TEST_POSTGRES` to a connection URL. Each
test runs in its own schema.

Copyright 2026 Ulrich Holtzhausen. Licensed under the Apache License, Version 2.0.
