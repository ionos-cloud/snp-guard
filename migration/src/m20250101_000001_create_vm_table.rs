// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("vm_registrations"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("id"))
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("os_name")).string().not_null())
                    .col(
                        ColumnDef::new(Alias::new("enabled"))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(Alias::new("request_count"))
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Alias::new("current_record_id"))
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("pending_record_id"))
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("id_key_digest"))
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("auth_key_digest"))
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("id_key_encrypted"))
                            .binary_len(4096)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("auth_key_encrypted"))
                            .binary_len(4096)
                            .null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("created_at"))
                            .date_time()
                            .not_null(),
                    )
                    .index(
                        Index::create()
                            .name("idx_vm_registrations_digests_unique")
                            .col(Alias::new("id_key_digest"))
                            .col(Alias::new("auth_key_digest"))
                            .unique(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("vm_registrations"))
                    .to_owned(),
            )
            .await
    }
}
