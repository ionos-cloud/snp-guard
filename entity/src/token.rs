// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String, // uuid
    pub label: String,
    pub token_hash: String,
    pub created_at: DateTime,
    pub expires_at: Option<DateTime>,
    pub revoked: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
