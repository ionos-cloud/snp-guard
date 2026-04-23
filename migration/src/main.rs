// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use migration::Migrator;
use sea_orm_migration::prelude::*;

#[async_std::main]
async fn main() {
    cli::run_cli(Migrator).await;
}
