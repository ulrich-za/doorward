# doorward-sqlite

SQLite storage for [doorward](https://crates.io/crates/doorward), the
headless sign-in library.

```rust,ignore
let store = doorward_sqlite::SqliteStore::open("/var/lib/myapp/myapp.db")?;
let dw = doorward::Doorward::builder(store)
    .address(doorward::Address::new("https://myapp.example")?)
    .build()
    .await?;
```

- doorward's tables are prefixed `auth_` and upgraded by doorward, so they can
  share the app's own database file.
- WAL mode, foreign keys, `secure_delete` (deleted rows are overwritten), and a
  five-second busy timeout.
- A file this crate creates is readable by its owner only (Unix).
- rusqlite is accepted from 0.40.2 up to 0.41, so an app on any of those shares
  one SQLite.
- The `bundled` feature (default) builds SQLite in.

Copyright 2026 Ulrich Holtzhausen. Licensed under the Apache License, Version 2.0.
