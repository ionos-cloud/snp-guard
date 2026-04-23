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
                    .table(Alias::new("tokens"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("id"))
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("label")).string().not_null())
                    .col(ColumnDef::new(Alias::new("token_hash")).string().not_null())
                    .col(
                        ColumnDef::new(Alias::new("created_at"))
                            .date_time()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alias::new("expires_at")).date_time().null())
                    .col(
                        ColumnDef::new(Alias::new("revoked"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Alias::new("tokens")).to_owned())
            .await
    }
}
