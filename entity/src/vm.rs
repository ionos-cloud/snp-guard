// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 IONOS SE
// Author: Roman Penyaev <r.peniaev@gmail.com>

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Versioned attestation artifact snapshot for a VM registration.
///
/// Each record captures a specific set of launch artifacts (firmware, kernel,
/// initrd, kernel params) together with the cryptographic material generated
/// from them (measurement, image_id).  The id/auth key material lives on the
/// parent VmRegistration and is stable across renewals.
///
/// A VmRegistration always has exactly one current record and at most one
/// pending record (created by a renewal call).
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "attestation_records")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String, // UUID
    /// Parent VmRegistration.
    pub registration_id: String,
    #[sea_orm(column_type = "Binary(4096)", nullable)]
    pub unsealing_private_key_encrypted: Vec<u8>,
    pub vcpus: i32,
    pub vcpu_type: String,
    #[sea_orm(column_type = "Binary(16)")]
    pub image_id: Vec<u8>, // 16-byte random identifier embedded in the SNP report

    // Guest policy flags
    pub allowed_debug: bool,
    pub allowed_migrate_ma: bool,
    pub allowed_smt: bool,

    // TCB minimum version requirements
    pub min_tcb_bootloader: i32,
    pub min_tcb_tee: i32,
    pub min_tcb_snp: i32,
    pub min_tcb_microcode: i32,

    pub created_at: DateTime,

    // Artifact paths relative to the record's artifact directory.
    // Nullable because a renewal may update only a subset of artifacts;
    // absent fields are inherited from the previous current record on the
    // server side before measurement is computed.
    pub firmware_path: Option<String>,
    pub kernel_path: Option<String>,
    pub initrd_path: Option<String>,
    pub kernel_params: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
