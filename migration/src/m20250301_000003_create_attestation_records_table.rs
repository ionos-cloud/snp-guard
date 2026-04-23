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
                    .table(Alias::new("attestation_records"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("id"))
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("registration_id"))
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("unsealing_private_key_encrypted"))
                            .binary_len(4096)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("vcpus"))
                            .integer()
                            .not_null()
                            .default(4),
                    )
                    .col(ColumnDef::new(Alias::new("vcpu_type")).string().not_null())
                    .col(
                        ColumnDef::new(Alias::new("image_id"))
                            .binary_len(16)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("allowed_debug"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(Alias::new("allowed_migrate_ma"))
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(Alias::new("allowed_smt"))
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(Alias::new("min_tcb_bootloader"))
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Alias::new("min_tcb_tee"))
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Alias::new("min_tcb_snp"))
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Alias::new("min_tcb_microcode"))
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(Alias::new("created_at"))
                            .date_time()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alias::new("firmware_path")).string().null())
                    .col(ColumnDef::new(Alias::new("kernel_path")).string().null())
                    .col(ColumnDef::new(Alias::new("initrd_path")).string().null())
                    .col(ColumnDef::new(Alias::new("kernel_params")).string().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("attestation_records"))
                    .to_owned(),
            )
            .await
    }
}
