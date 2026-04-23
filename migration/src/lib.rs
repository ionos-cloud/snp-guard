// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

pub use sea_orm_migration::prelude::*;

mod m20250101_000001_create_vm_table;
mod m20250201_000002_create_tokens_table;
mod m20250301_000003_create_attestation_records_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250101_000001_create_vm_table::Migration),
            Box::new(m20250201_000002_create_tokens_table::Migration),
            Box::new(m20250301_000003_create_attestation_records_table::Migration),
        ]
    }
}
