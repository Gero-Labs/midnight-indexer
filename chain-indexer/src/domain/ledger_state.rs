// This file is part of midnight-indexer.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::domain::{RegularTransaction, SystemTransaction, Transaction, node};
use derive_more::derive::{Deref, From};
use fastrace::trace;
use indexer_common::domain::{
    ApplyRegularTransactionOutcome, ApplySystemTransactionOutcome, BlockHash, LedgerVersion,
    NetworkId, SerializedContractAddress, SerializedLedgerStateKey, TransactionHash,
    ledger::{self, LedgerParameters},
};
use log::warn;
use std::ops::DerefMut;
use thiserror::Error;

/// The node bumps a mempool transaction's well-formed `tblock` two slots (2 × 6s) ahead of the
/// parent block time; reproduce that same offset here. See `apply_transactions`.
const MEMPOOL_TBLOCK_BUMP_MILLIS: u64 = 2 * 6_000;

/// New type for ledger state from indexer_common.
#[derive(Debug, Clone, From, Deref)]
pub struct LedgerState(pub indexer_common::domain::ledger::LedgerState);

impl DerefMut for LedgerState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl LedgerState {
    pub fn new(network_id: NetworkId, ledger_version: LedgerVersion) -> Result<Self, Error> {
        indexer_common::domain::ledger::LedgerState::new(network_id, ledger_version)
            .map_err(Error::Create)
            .map(Into::into)
    }

    pub fn from_genesis(
        raw: impl AsRef<[u8]>,
        ledger_version: LedgerVersion,
    ) -> Result<Self, Error> {
        indexer_common::domain::ledger::LedgerState::from_genesis(raw, ledger_version)
            .map_err(Error::Create)
            .map(Into::into)
    }

    pub fn load(
        key: &SerializedLedgerStateKey,
        ledger_version: LedgerVersion,
    ) -> Result<Self, Error> {
        indexer_common::domain::ledger::LedgerState::load(key, ledger_version)
            .map_err(Error::Load)
            .map(Into::into)
    }

    pub fn translate(self, ledger_version: LedgerVersion) -> Result<Self, Error> {
        self.0
            .translate(ledger_version)
            .map_err(Error::Translate)
            .map(Into::into)
    }

    /// Apply the given node transactions to this ledger state and return domain transactions.
    ///
    /// `bump_first_regular_tblock` selects whether the node's mempool-cached validity result is
    /// reproduced for the first regular transaction (see below). It must be `false` for the genesis
    /// block (height 0): the transactions embedded in genesis never transited the mempool, so the
    /// node never cached a bumped result for them and validated them against the real block time.
    /// Bumping them would push the well-formed `tblock` past a bootstrap transaction's intent TTL
    /// and wrongly reject it.
    #[trace(properties = { "parent_block_hash": "{parent_block_hash}" })]
    pub fn apply_transactions(
        &mut self,
        transactions: impl IntoIterator<Item = node::Transaction>,
        parent_block_hash: BlockHash,
        block_timestamp: u64,
        parent_block_timestamp: u64,
        bump_first_regular_tblock: bool,
    ) -> Result<(Vec<Transaction>, LedgerParameters), Error> {
        // The node validates a mempool transaction against a `tblock` bumped two slots ahead of the
        // *parent* (last produced) block's time, then caches the well-formed result keyed on
        // (tx_hash, ledger_state_key). At block inclusion only the first regular transaction still
        // matches that key, so the node reuses the cached (bumped) validity result and skips
        // re-checking it against the real block time; later transactions get a fresh check against
        // block time. The bump base is the parent block time (`get_block_context().tblock` during
        // pool validation still holds the last produced block's timestamp; see the node's
        // `pallet-midnight` `validate_unsigned`), NOT the current block time — bumping from the
        // current block overshoots by the inter-block gap and can push `tblock` past a
        // transaction's intent TTL, wrongly rejecting a tx the node accepted.
        //
        // Reproduce that by bumping only the first regular transaction's well-formed `tblock` off
        // the parent block time. `apply` always runs against the real block time, so the resulting
        // state matches the node.
        let mut first_regular_transaction = true;
        let transactions = transactions
            .into_iter()
            .map(|transaction| match transaction {
                node::Transaction::Regular(transaction) => {
                    let well_formed_timestamp =
                        if first_regular_transaction && bump_first_regular_tblock {
                            parent_block_timestamp + MEMPOOL_TBLOCK_BUMP_MILLIS
                        } else {
                            block_timestamp
                        };
                    first_regular_transaction = false;

                    self.apply_regular_transaction(
                        transaction,
                        parent_block_hash,
                        block_timestamp,
                        parent_block_timestamp,
                        well_formed_timestamp,
                    )
                }

                node::Transaction::System(transaction) => {
                    self.apply_system_transaction(transaction, block_timestamp)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let ledger_parameters = self
            .finalize_apply_transactions(block_timestamp)
            .map_err(Error::PostApplyTransactions)?;

        Ok((transactions, ledger_parameters))
    }

    /// The highest used zswap state index or none.
    pub fn highest_zswap_state_index(&self) -> Option<u64> {
        (self.zswap_first_free() != 0).then(|| self.zswap_first_free() - 1)
    }

    #[trace(properties = {
        "parent_block_hash": "{parent_block_hash}",
        "block_timestamp": "{block_timestamp}",
        "well_formed_timestamp": "{well_formed_timestamp}"
    })]
    fn apply_regular_transaction(
        &mut self,
        transaction: node::RegularTransaction,
        parent_block_hash: BlockHash,
        block_timestamp: u64,
        parent_block_timestamp: u64,
        well_formed_timestamp: u64,
    ) -> Result<Transaction, Error> {
        let mut transaction = RegularTransaction::from(transaction);

        // Apply transaction.
        let start_index = self.zswap_first_free();
        let dust_commitment_start_index = self.dust_commitments_first_free();
        let dust_generation_start_index = self.dust_generations_first_free();
        let ApplyRegularTransactionOutcome {
            transaction_result,
            created_unshielded_utxos,
            spent_unshielded_utxos,
            ledger_events,
            fees,
        } = self
            .0
            .apply_regular_transaction(
                &transaction.raw,
                parent_block_hash,
                block_timestamp,
                parent_block_timestamp,
                well_formed_timestamp,
            )
            .or_else(|error| match error {
                // The bumped `tblock` is only what the node used when its mempool cache was warm;
                // with a cold cache it validated the transaction at block time instead, and nothing
                // in the block records which. Mainnet block 1788980 and preprod block 164460 hold
                // first transactions whose intent TTL lies between block time and the bumped
                // `tblock`. So, like the node (midnightntwrk/midnight-node#2216) and upstream
                // (midnightntwrk/midnight-indexer#1610), accept the transaction if it is
                // well-formed at either `tblock`. `well_formed` fails before the ledger state is
                // touched, so retrying is safe, and `apply` always runs at block time.
                ledger::Error::MalformedTransaction(_)
                    if well_formed_timestamp != block_timestamp =>
                {
                    warn!(
                        transaction_hash:% = transaction.hash,
                        block_timestamp,
                        well_formed_timestamp,
                        error:%;
                        "first regular transaction malformed at bumped tblock, retrying at block time"
                    );
                    self.0.apply_regular_transaction(
                        &transaction.raw,
                        parent_block_hash,
                        block_timestamp,
                        parent_block_timestamp,
                        block_timestamp,
                    )
                }

                error => Err(error),
            })
            .map_err(|error| Error::ApplyRegularTransaction(Some(transaction.hash), error))?;

        // Update transaction.
        transaction.transaction_result = transaction_result;
        transaction.zswap_merkle_tree_root = self
            .zswap_merkle_tree_root()
            .serialize()
            .map_err(|error| Error::SerializeMerkleTreeRoot(transaction.hash, error))?;
        transaction.zswap_start_index = start_index;
        transaction.zswap_end_index = self.zswap_first_free();
        transaction.dust_commitment_start_index = dust_commitment_start_index;
        transaction.dust_commitment_end_index = self.dust_commitments_first_free();
        transaction.dust_generation_start_index = dust_generation_start_index;
        transaction.dust_generation_end_index = self.dust_generations_first_free();
        transaction.created_unshielded_utxos = created_unshielded_utxos;
        transaction.spent_unshielded_utxos = spent_unshielded_utxos;
        transaction.ledger_events = ledger_events;
        transaction.paid_fees = fees;
        transaction.estimated_fees = fees;

        // Update contract actions.
        for contract_action in transaction.contract_actions.iter_mut() {
            let zswap_state = self
                .extract_contract_zswap_state(&contract_action.address)
                .map_err(|error| Error::ExtractContractZswapState(transaction.hash, error))?;
            contract_action.zswap_state = zswap_state;

            // TODO: Workaround until we filter failed contract actions (empty state means failed).
            if !contract_action.state.is_empty() {
                let contract_state = ledger::ContractState::deserialize(
                    &contract_action.state,
                    transaction.protocol_version.ledger_version(),
                )
                .map_err(|error| {
                    Error::DeserializeContractState(
                        transaction.hash,
                        contract_action.address.clone(),
                        error,
                    )
                })?;
                let balances = contract_state.balances().map_err(|error| {
                    Error::GetContractBalances(
                        transaction.hash,
                        contract_action.address.clone(),
                        error,
                    )
                })?;
                contract_action.extracted_balances = balances;
            }
        }

        Ok(Transaction::Regular(transaction.into()))
    }

    #[trace(properties = {
        "block_timestamp": "{block_timestamp}"
    })]
    fn apply_system_transaction(
        &mut self,
        transaction: node::SystemTransaction,
        block_timestamp: u64,
    ) -> Result<Transaction, Error> {
        let mut transaction = SystemTransaction::from(transaction);

        // Apply transaction.
        let ApplySystemTransactionOutcome {
            created_unshielded_utxos,
            ledger_events,
        } = self
            .0
            .apply_system_transaction(&transaction.raw, block_timestamp)
            .map_err(|error| Error::ApplySystemTransaction(Some(transaction.hash), error))?;

        // Update transaction.
        transaction.created_unshielded_utxos = created_unshielded_utxos;
        transaction.ledger_events = ledger_events;

        Ok(Transaction::System(transaction))
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Create(indexer_common::domain::ledger::Error),

    #[error(transparent)]
    Load(indexer_common::domain::ledger::Error),

    #[error(transparent)]
    Translate(indexer_common::domain::ledger::Error),

    #[error("cannot apply regular transaction {hash}", hash = stringify_hash(.0))]
    ApplyRegularTransaction(
        Option<TransactionHash>,
        #[source] indexer_common::domain::ledger::Error,
    ),

    #[error("cannot apply system transaction {hash}", hash = stringify_hash(.0))]
    ApplySystemTransaction(
        Option<TransactionHash>,
        #[source] indexer_common::domain::ledger::Error,
    ),

    #[error("cannot finalize transaction application")]
    PostApplyTransactions(#[source] indexer_common::domain::ledger::Error),

    #[error("cannot serialize Merkle tree root for transaction {0}")]
    SerializeMerkleTreeRoot(
        TransactionHash,
        #[source] indexer_common::domain::ledger::Error,
    ),

    #[error("cannot extract contract zswap state for transaction {0}")]
    ExtractContractZswapState(
        TransactionHash,
        #[source] indexer_common::domain::ledger::Error,
    ),

    #[error("cannot deserialize contract state for transaction {0} and contract address {1}")]
    DeserializeContractState(
        TransactionHash,
        SerializedContractAddress,
        #[source] indexer_common::domain::ledger::Error,
    ),

    #[error("cannot get contract balances for transaction {0} and contract address {1}")]
    GetContractBalances(
        TransactionHash,
        SerializedContractAddress,
        #[source] indexer_common::domain::ledger::Error,
    ),
}

fn stringify_hash(hash: &Option<TransactionHash>) -> String {
    hash.map(|hash| hash.to_string())
        .unwrap_or_else(|| "<hash unavailable>".to_string())
}

#[cfg(all(test, feature = "standalone"))]
mod tests {
    use crate::domain::{LedgerState, Transaction, node};
    use anyhow::Context;
    use indexer_common::{
        domain::{BlockHash, ProtocolVersion, SerializedTransaction, TransactionHash, ledger},
        error::BoxError,
        infra::{
            ledger_db, migrations,
            pool::{self, sqlite::SqlitePool},
        },
    };
    use std::{error::Error as StdError, fs, iter};

    // Mainnet block 1788980's first (and only) regular transaction: parent 1784643552, block
    // 1784643558, intent TTL 1784643562. The node accepted it at block time; the bumped `tblock`
    // 1784643564 is past the TTL. Fixture from midnightntwrk/midnight-indexer#1610.
    #[tokio::test(flavor = "multi_thread")]
    async fn mainnet_1788980_ttl_between_the_tblocks_is_accepted() -> Result<(), BoxError> {
        let _temp_dir = init_ledger_db().await?;
        let error = apply_one(
            "mainnet",
            ProtocolVersion::V1_0(1_000_000),
            "block_1788980_tx.raw",
            "e769b82781bbfd1e29d602a17916abe6e967ef023eb94d23a4aa8b88a6e35c0a",
            1_784_643_558,
            1_784_643_552,
        )?;

        // Against a fresh state instead of mainnet's, the transaction passes the time checks and
        // fails the next stateful check: the contract it calls does not exist.
        assert!(error.contains("call to non-existant contract"), "{error}");
        Ok(())
    }

    // Preprod block 164460's first (and only) regular transaction: parent 1775081610, block
    // 1775081616, intent TTL 1775081620; the bumped `tblock` 1775081622 is past the TTL.
    #[tokio::test(flavor = "multi_thread")]
    async fn preprod_164460_ttl_between_the_tblocks_is_accepted() -> Result<(), BoxError> {
        let _temp_dir = init_ledger_db().await?;
        let error = apply_one(
            "preprod",
            ProtocolVersion::V0_22(22_000),
            "block_164460_tx.raw",
            "6a1005eecf695a8f950e8f8e74de0c6336daf55448326bf0db0b3b55c089ad0b",
            1_775_081_616,
            1_775_081_610,
        )?;

        assert!(error.contains("call to non-existant contract"), "{error}");
        Ok(())
    }

    // Applies one fixture transaction as the first regular transaction of a block, with the bump,
    // to a fresh ledger state and returns the rejection error. Times are in seconds.
    fn apply_one(
        network_id: &str,
        protocol_version: ProtocolVersion,
        file_name: &str,
        hash: &str,
        block_time: u64,
        parent_block_time: u64,
    ) -> Result<String, BoxError> {
        let ledger_version = protocol_version.ledger_version();
        let raw: SerializedTransaction = fs::read(format!(
            "{}/../indexer-common/tests/{file_name}",
            env!("CARGO_MANIFEST_DIR")
        ))?
        .into();
        let transaction = ledger::Transaction::deserialize(&raw, ledger_version)?;
        assert_eq!(transaction.hash(), TransactionHash::from_hex(hash)?);

        let transaction = node::Transaction::Regular(node::RegularTransaction {
            hash: transaction.hash(),
            protocol_version,
            identifiers: transaction.identifiers()?,
            raw,
            contract_actions: vec![],
        });

        let mut ledger_state = LedgerState::new(network_id.try_into()?, ledger_version)?;
        match ledger_state.apply_transactions(
            [transaction],
            BlockHash::from([0; 32]),
            block_time * 1_000,
            parent_block_time * 1_000,
            true,
        ) {
            Ok((transactions, _)) => Err(format!(
                "expected a rejection, got {:?}",
                transactions
                    .iter()
                    .filter_map(|transaction| match transaction {
                        Transaction::Regular(transaction) => Some(&transaction.transaction_result),
                        Transaction::System(_) => None,
                    })
                    .collect::<Vec<_>>()
            )
            .into()),
            // Include the source chain: the ledger's reason is in the sources.
            Err(error) => {
                Ok(
                    iter::successors(Some(&error as &dyn StdError), |&error| error.source())
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(": "),
                )
            }
        }
    }

    async fn init_ledger_db() -> Result<tempfile::TempDir, BoxError> {
        let temp_dir = tempfile::tempdir().context("create tempdir")?;
        let pool = SqlitePool::new(pool::sqlite::Config {
            cnn_url: temp_dir.path().join("indexer.sqlite").display().to_string(),
        })
        .await
        .context("create pool")?;
        migrations::sqlite::run(&pool)
            .await
            .context("run migrations")?;
        ledger_db::init(ledger_db::Config {
            cache_size: 1_024,
            cnn_url: temp_dir
                .path()
                .join("ledger-db.sqlite")
                .display()
                .to_string(),
        })
        .await
        .context("init ledger DB")?;
        Ok(temp_dir)
    }
}
