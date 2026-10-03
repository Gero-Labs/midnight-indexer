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
    TransactionResult,
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
    /// reproduced for the regular transactions before the first one that applies (see below). It
    /// must be `false` for the genesis block (height 0): the transactions embedded in genesis
    /// never transited the mempool, so the node never cached a bumped result for them and
    /// validated them against the real block time. Bumping them would push the well-formed
    /// `tblock` past a bootstrap transaction's intent TTL and wrongly reject it.
    #[trace(properties = { "parent_block_hash": "{parent_block_hash}" })]
    pub fn apply_transactions(
        &mut self,
        transactions: impl IntoIterator<Item = node::Transaction>,
        parent_block_hash: BlockHash,
        block_timestamp: u64,
        parent_block_timestamp: u64,
        bump_first_regular_tblock: bool,
    ) -> Result<(Vec<Transaction>, LedgerParameters), Error> {
        // The node validates a pool transaction at the parent block time plus two slots (see its
        // `pallet-midnight` `validate_unsigned`) and caches the result keyed on the ledger state.
        // At inclusion the cache hits only while the state is still the parent's, i.e. before a
        // regular transaction applies (a failed one leaves the state unchanged), so such a
        // transaction is verified at that bumped `tblock` and later ones at the block time. The
        // base is the parent time, not the block time: bumping from the block overshoots by the
        // inter-block gap.
        //
        // The cache misses if the author validated the transaction against an older state, and
        // the block does not record which (mainnet block 1788980, preprod block 164460). So, like
        // midnightntwrk/midnight-indexer#1610 and the node (midnightntwrk/midnight-node#2216),
        // verify at the block time and, if malformed there, at the bumped `tblock`. `apply` always
        // runs at the block time, so the state matches the node.
        let mut no_regular_transaction_applied = true;
        let transactions = transactions
            .into_iter()
            .map(|transaction| match transaction {
                node::Transaction::Regular(transaction) => {
                    let well_formed_timestamp = (no_regular_transaction_applied
                        && bump_first_regular_tblock)
                        .then_some(parent_block_timestamp + MEMPOOL_TBLOCK_BUMP_MILLIS);

                    let transaction = self.apply_regular_transaction(
                        transaction,
                        parent_block_hash,
                        block_timestamp,
                        parent_block_timestamp,
                        well_formed_timestamp,
                    )?;
                    if let Transaction::Regular(transaction) = &transaction {
                        no_regular_transaction_applied &=
                            transaction.transaction_result == TransactionResult::Failure;
                    }

                    Ok(transaction)
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
        "well_formed_timestamp": "{well_formed_timestamp:?}"
    })]
    fn apply_regular_transaction(
        &mut self,
        transaction: node::RegularTransaction,
        parent_block_hash: BlockHash,
        block_timestamp: u64,
        parent_block_timestamp: u64,
        well_formed_timestamp: Option<u64>,
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
        } = {
            let mut apply = |well_formed_timestamp| {
                self.0.apply_regular_transaction(
                    &transaction.raw,
                    parent_block_hash,
                    block_timestamp,
                    parent_block_timestamp,
                    well_formed_timestamp,
                )
            };

            // Verify at the block time and, if malformed there, at `well_formed_timestamp`. A
            // malformed transaction leaves the ledger state untouched (`well_formed` fails before
            // `apply`), so the retry applies to the same state. The error reported is the one at
            // block time.
            match (apply(block_timestamp), well_formed_timestamp) {
                (
                    Err(error @ ledger::Error::MalformedTransaction(_)),
                    Some(well_formed_timestamp),
                ) => apply(well_formed_timestamp).map_err(|retry_error| {
                    warn!(
                        transaction_hash:% = transaction.hash,
                        parent_block_hash:%,
                        block_timestamp,
                        well_formed_timestamp,
                        retry_error:%;
                        "regular transaction malformed at the bumped tblock as well"
                    );
                    error
                }),

                (outcome, _) => outcome,
            }
        }
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
        domain::{
            BlockHash, LedgerVersion, ProtocolVersion, SerializedTransaction, TransactionHash,
            TransactionResult,
            ledger::{self, TaggedSerializableExt},
        },
        error::BoxError,
        infra::{
            ledger_db::{self, v1_1::LedgerDb},
            migrations,
            pool::{self, sqlite::SqlitePool},
        },
    };
    use midnight_base_crypto_v1::{
        signatures::{Signature, SigningKey},
        time::Timestamp,
    };
    use midnight_ledger_v8::{
        dust::{DustActions, DustPublicKey, DustRegistration, DustSecretKey},
        error::{MalformedTransaction, TransactionApplicationError},
        structure::{Intent, ProofPreimageMarker, Transaction as LedgerTransaction},
    };
    use midnight_onchain_runtime_v3::cost_model::INITIAL_COST_MODEL;
    use midnight_storage_core_v1::arena::Sp;
    use midnight_transient_crypto_v2::{
        commitment::PedersenRandomness,
        curve::Fr,
        proofs::{Proof, ProofPreimage, ProvingProvider},
    };
    use rand::{SeedableRng, rngs::StdRng};
    use std::{error::Error as StdError, fs, iter};

    // Network ID of the synthetic transactions.
    const NETWORK_ID: &str = "undeployed";

    // Block time of every synthetic test block, in seconds. Each case sets its parent block time
    // relative to it, and the bumped `tblock` is `parent + 12s`.
    const NOW: u64 = 1_800_000_000;

    // A reason the ledger rejects a transaction as malformed.
    #[derive(Debug, PartialEq, Eq)]
    enum Malformed {
        IntentTtlExpired,
        OutOfDustValidityWindow,
        // Any other malformed-transaction error, as displayed.
        Other(String),
    }

    // One block applied at `NOW` to a fresh ledger state. Times are in seconds.
    struct Case {
        name: &'static str,
        // Intent TTL and dust `ctime` of each regular transaction.
        transactions: &'static [(u64, u64)],
        parent_block_time: u64,
        bump_first_regular_tblock: bool,
        expected: Result<Vec<TransactionResult>, Malformed>,
    }

    // Ported from midnightntwrk/midnight-indexer#1610 (ledger 8 only): a regular transaction is
    // accepted if well-formed at the block time or at the bumped `tblock` until one applies; from
    // then on only at the block time.
    #[tokio::test(flavor = "multi_thread")]
    async fn regular_transactions_are_accepted_at_the_bumped_tblock_until_one_applies()
    -> Result<(), BoxError> {
        use Malformed::{IntentTtlExpired, OutOfDustValidityWindow};
        use TransactionResult::{Failure, Success};

        let _temp_dir = init_ledger_db().await?;
        let protocol_version = ProtocolVersion::V1_0(1_000_000);

        let cases = [
            // With the parent block in the previous 6s slot the bumped `tblock` is `NOW + 6s`. A
            // dust `ctime` of `NOW + 4s` is valid there but not at the block time, and only the
            // transactions before the first applied one are retried there.
            Case {
                name: "dust ctime ahead, bumped",
                transactions: &[(NOW + 60, NOW + 4)],
                parent_block_time: NOW - 6,
                bump_first_regular_tblock: true,
                expected: Ok(vec![Success]),
            },
            Case {
                name: "dust ctime ahead, not bumped",
                transactions: &[(NOW + 60, NOW + 4)],
                parent_block_time: NOW - 6,
                bump_first_regular_tblock: false,
                expected: Err(OutOfDustValidityWindow),
            },
            Case {
                name: "dust ctime ahead, second transaction",
                transactions: &[(NOW + 60, NOW), (NOW + 60, NOW + 4)],
                parent_block_time: NOW - 6,
                bump_first_regular_tblock: true,
                expected: Err(OutOfDustValidityWindow),
            },
            // `NOW + 6s` is past an intent TTL of `NOW + 2s`; the block time is not.
            Case {
                name: "ttl before bumped tblock, bumped",
                transactions: &[(NOW + 2, NOW)],
                parent_block_time: NOW - 6,
                bump_first_regular_tblock: true,
                expected: Ok(vec![Success]),
            },
            // With the two slots before the block skipped the bumped `tblock` is `NOW - 6s`,
            // before the block time. An intent TTL of `NOW - 5s` passes `well_formed` there, and
            // `apply` fails it at the block time.
            Case {
                name: "ttl before block time, bumped",
                transactions: &[(NOW - 5, NOW - 18)],
                parent_block_time: NOW - 18,
                bump_first_regular_tblock: true,
                expected: Ok(vec![Failure]),
            },
            Case {
                name: "ttl before block time, not bumped",
                transactions: &[(NOW - 5, NOW - 18)],
                parent_block_time: NOW - 18,
                bump_first_regular_tblock: false,
                expected: Err(IntentTtlExpired),
            },
            // A dust `ctime` of `NOW - 5s` is past `NOW - 6s` but valid at the block time.
            Case {
                name: "dust ctime after bumped tblock, bumped",
                transactions: &[(NOW + 40, NOW - 5)],
                parent_block_time: NOW - 18,
                bump_first_regular_tblock: true,
                expected: Ok(vec![Success]),
            },
            // Malformed at both `tblock`s, with a different error at each: the error at the block
            // time is reported.
            Case {
                name: "malformed at both, bumped tblock after the block time",
                transactions: &[(NOW + 2, NOW + 4)],
                parent_block_time: NOW - 6,
                bump_first_regular_tblock: true,
                expected: Err(OutOfDustValidityWindow),
            },
            Case {
                name: "malformed at both, bumped tblock before the block time",
                transactions: &[(NOW - 5, NOW - 5)],
                parent_block_time: NOW - 18,
                bump_first_regular_tblock: true,
                expected: Err(IntentTtlExpired),
            },
            // A failed regular transaction leaves the state unchanged, so the next one is still
            // verified at the bumped `tblock` `NOW - 6s`: an intent TTL of `NOW - 3s` passes
            // `well_formed` there, and `apply` fails it at the block time as well. This is the
            // case catchup.4 (first transaction only) got wrong.
            Case {
                name: "ttl before block time, after a failed transaction",
                transactions: &[(NOW - 5, NOW - 18), (NOW - 3, NOW - 18)],
                parent_block_time: NOW - 18,
                bump_first_regular_tblock: true,
                expected: Ok(vec![Failure, Failure]),
            },
        ];

        for case in cases {
            let mut transactions = vec![];
            for &(ttl, ctime) in case.transactions {
                transactions.push(dust_registration(ttl, ctime).await?);
            }

            assert_eq!(
                apply(
                    NETWORK_ID,
                    protocol_version,
                    &transactions,
                    NOW,
                    case.parent_block_time,
                    case.bump_first_regular_tblock,
                )?,
                case.expected,
                "{}",
                case.name
            );
        }

        Ok(())
    }

    // Mainnet block 1788980's first (and only) regular transaction: parent 1784643552, block
    // 1784643558, intent TTL 1784643562. The node accepted it at block time; the bumped `tblock`
    // 1784643564 is past the TTL. Fixture from midnightntwrk/midnight-indexer#1610.
    #[tokio::test(flavor = "multi_thread")]
    async fn mainnet_1788980_ttl_between_the_tblocks_is_accepted() -> Result<(), BoxError> {
        let _temp_dir = init_ledger_db().await?;
        let transaction = fixture(
            "block_1788980_tx.raw",
            "e769b82781bbfd1e29d602a17916abe6e967ef023eb94d23a4aa8b88a6e35c0a",
        )?;

        // Against a fresh state instead of mainnet's, the transaction passes the time checks and
        // fails the next stateful check: the contract it calls does not exist.
        assert_eq!(
            apply(
                "mainnet",
                ProtocolVersion::V1_0(1_000_000),
                &[transaction],
                1_784_643_558,
                1_784_643_552,
                true,
            )?,
            Err(Malformed::Other(
                "call to non-existant contract ContractAddress(4fd31443997bd04bbf0b94e2ef3d5b0ff05479c4fb80bcac0dc74b2c763282e5)"
                    .to_string()
            ))
        );
        Ok(())
    }

    // Preprod block 164460's first (and only) regular transaction: parent 1775081610, block
    // 1775081616, intent TTL 1775081620; the bumped `tblock` 1775081622 is past the TTL.
    #[tokio::test(flavor = "multi_thread")]
    async fn preprod_164460_ttl_between_the_tblocks_is_accepted() -> Result<(), BoxError> {
        let _temp_dir = init_ledger_db().await?;
        let transaction = fixture(
            "block_164460_tx.raw",
            "6a1005eecf695a8f950e8f8e74de0c6336daf55448326bf0db0b3b55c089ad0b",
        )?;

        assert_eq!(
            apply(
                "preprod",
                ProtocolVersion::V0_22(22_000),
                &[transaction],
                1_775_081_616,
                1_775_081_610,
                true,
            )?,
            Err(Malformed::Other(
                "call to non-existant contract ContractAddress(18835f54e98cfbf5c789ef76fb79d4cb0e8d84d627ef1e36cdf27cf3cdbaebb7)"
                    .to_string()
            ))
        );
        Ok(())
    }

    // Applies `transactions` as one block to a fresh ledger state of `network_id`; the outer error
    // is a test setup failure, the inner one the reason the ledger rejects a transaction. Times
    // are in seconds.
    fn apply(
        network_id: &str,
        protocol_version: ProtocolVersion,
        transactions: &[SerializedTransaction],
        block_time: u64,
        parent_block_time: u64,
        bump_first_regular_tblock: bool,
    ) -> Result<Result<Vec<TransactionResult>, Malformed>, BoxError> {
        let ledger_version = protocol_version.ledger_version();
        let mut ledger_state = LedgerState::new(network_id.try_into()?, ledger_version)?;
        let transactions = transactions
            .iter()
            .map(|raw| {
                let transaction = ledger::Transaction::deserialize(raw, ledger_version)?;
                Ok(node::Transaction::Regular(node::RegularTransaction {
                    hash: transaction.hash(),
                    protocol_version,
                    raw: raw.clone(),
                    identifiers: transaction.identifiers()?,
                    contract_actions: vec![],
                }))
            })
            .collect::<Result<Vec<_>, BoxError>>()?;

        match ledger_state.apply_transactions(
            transactions,
            BlockHash::from([0; 32]),
            block_time * 1_000,
            parent_block_time * 1_000,
            bump_first_regular_tblock,
        ) {
            Ok((transactions, _)) => Ok(Ok(transactions
                .into_iter()
                .filter_map(|transaction| match transaction {
                    Transaction::Regular(transaction) => Some(transaction.transaction_result),
                    Transaction::System(_) => None,
                })
                .collect())),
            Err(error) => malformed(&error)
                .map(Err)
                .ok_or_else(|| format!("unexpected error: {error}").into()),
        }
    }

    // Returns why the ledger rejected a transaction as malformed, if `error` or any of its sources
    // reports it.
    fn malformed(error: &(dyn StdError + 'static)) -> Option<Malformed> {
        iter::successors(Some(error), |&error| error.source()).find_map(|error| {
            error.downcast_ref::<MalformedTransaction<LedgerDb>>().map(
                |malformed| match malformed {
                    MalformedTransaction::TransactionApplicationError(
                        TransactionApplicationError::IntentTtlExpired(..),
                    ) => Malformed::IntentTtlExpired,
                    MalformedTransaction::OutOfDustValidityWindow { .. } => {
                        Malformed::OutOfDustValidityWindow
                    }
                    other => Malformed::Other(other.to_string()),
                },
            )
        })
    }

    // Builds a serialized ledger-8 transaction whose single intent carries only a signed dust
    // registration. It needs no proofs, so it applies to a fresh ledger state for [NETWORK_ID].
    // Times are in seconds. Ported from midnightntwrk/midnight-indexer#1610.
    async fn dust_registration(
        ttl: u64,
        dust_ctime: u64,
    ) -> Result<SerializedTransaction, BoxError> {
        let mut rng = StdRng::seed_from_u64(0);
        let night_key = SigningKey::sample(&mut rng);
        let registration = DustRegistration {
            night_key: night_key.verifying_key(),
            dust_address: Some(Sp::new(DustPublicKey::from(DustSecretKey::sample(
                &mut rng,
            )))),
            allow_fee_payment: 0,
            signature: None,
        };
        let dust_actions = DustActions::<Signature, ProofPreimageMarker, LedgerDb> {
            spends: vec![].into(),
            registrations: vec![registration].into(),
            ctime: Timestamp::from_secs(dust_ctime),
        };
        let intent = Intent::<_, _, PedersenRandomness, _>::new(
            &mut rng,
            None,
            None,
            vec![],
            vec![],
            vec![],
            Some(dust_actions),
            Timestamp::from_secs(ttl),
        )
        .sign(&mut rng, 1, &[], &[], &[night_key])
        .map_err(|error| format!("sign intent: {error}"))?;

        let transaction =
            LedgerTransaction::from_intents(NETWORK_ID, [(1, intent)].into_iter().collect())
                .prove(NoProofs, &INITIAL_COST_MODEL)
                .await
                .map_err(|error| format!("prove: {error}"))?
                .seal(rng)
                .tagged_serialize()?;

        Ok(transaction)
    }

    // Reads a real ledger-8 transaction from `indexer-common/tests` and checks its hash.
    fn fixture(file_name: &str, hash: &str) -> Result<SerializedTransaction, BoxError> {
        let raw: SerializedTransaction = fs::read(format!(
            "{}/../indexer-common/tests/{file_name}",
            env!("CARGO_MANIFEST_DIR")
        ))?
        .into();
        let transaction = ledger::Transaction::deserialize(&raw, LedgerVersion::V8)?;
        assert_eq!(
            transaction.hash(),
            TransactionHash::from_hex(hash)?,
            "{file_name}"
        );
        Ok(raw)
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

    // A proving provider for transactions without proofs; `prove` only ever calls `split` on it.
    struct NoProofs;

    impl ProvingProvider for NoProofs {
        async fn check(&self, _preimage: &ProofPreimage) -> anyhow::Result<Vec<Option<usize>>> {
            unreachable!("test transactions carry no proofs")
        }

        async fn prove(
            self,
            _preimage: &ProofPreimage,
            _overwrite_binding_input: Option<Fr>,
        ) -> anyhow::Result<Proof> {
            unreachable!("test transactions carry no proofs")
        }

        fn split(&mut self) -> Self {
            NoProofs
        }
    }
}
