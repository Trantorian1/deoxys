use std::fmt::Display;
use std::sync::MutexGuard;

use async_trait::async_trait;
use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use bitvec::view::AsBits;
use bonsai_trie::id::BasicId;
use bonsai_trie::BonsaiStorage;
use sp_core::hexdisplay::AsBytesRef;
use starknet_api::api_core::ContractAddress;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::Pedersen;
use thiserror::Error;

use crate::bonsai_db::BonsaiDb;
use crate::DeoxysBackend;

pub struct StorageHandler;

pub struct ContractTrieHandler<'a>(MutexGuard<'a, BonsaiStorage<BasicId, BonsaiDb, Pedersen>>);

pub struct ContractStorageTrieHandler<'a>(MutexGuard<'a, BonsaiStorage<BasicId, BonsaiDb, Pedersen>>);

pub struct ClassTrieHandler;

#[derive(Debug)]
pub enum StorageType {
    Contract,
    ContractStorage,
    Class,
}

impl Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let storage_type = match self {
            StorageType::Contract => "contract trie",
            StorageType::ContractStorage => "contract storage trie",
            StorageType::Class => "class trie",
        };

        write!(f, "{storage_type}")
    }
}

#[derive(Error, Debug)]
pub enum DeoxysStorageError {
    #[error("failed to insert data into {0}")]
    StorageInsertionError(StorageType),
    #[error("failed to retrive data from {0}")]
    StorageRetrievalError(StorageType),
    #[error("failed to compute trie root for {0}")]
    TrieRootError(StorageType),
}

mod bonsai_identifier {
    pub const CONTRACT: &[u8] = "0xcontract".as_bytes();
    pub const CLASS: &[u8] = "0xclass".as_bytes();
    pub const TRANSACTION: &[u8] = "0xtransaction".as_bytes();
    pub const EVENT: &[u8] = "0xevent".as_bytes();
}

trait TrieHandler<I, K, V> {
    fn insert(&mut self, identifier: &I, key: &K, value: V) -> Result<(), DeoxysStorageError>;

    fn get(&self, identifier: &I, key: &K) -> Result<Option<Felt>, DeoxysStorageError>;
}

impl<'a> StorageHandler {
    pub fn contract() -> ContractTrieHandler<'a> {
        ContractTrieHandler(DeoxysBackend::bonsai_contract().lock().unwrap())
    }

    pub fn contract_storage() -> ContractStorageTrieHandler<'a> {
        ContractStorageTrieHandler(DeoxysBackend::bonsai_storage().lock().unwrap())
    }

    pub fn class() -> ClassTrieHandler {
        ClassTrieHandler
    }
}

impl<'a> TrieHandler<ContractAddress, ContractAddress, Felt> for ContractTrieHandler<'a> {
    fn insert(
        &mut self,
        identifier: &ContractAddress,
        key: &ContractAddress,
        value: Felt,
    ) -> Result<(), DeoxysStorageError> {
        let identifier = conv_contract_identifier(identifier);
        let key = conv_contract_key(key);

        self.0
            .insert(identifier, &key, &value)
            .map_err(|_| DeoxysStorageError::StorageInsertionError(StorageType::Contract))?;

        Ok(())
    }

    fn get(&self, identifier: &ContractAddress, key: &ContractAddress) -> Result<Option<Felt>, DeoxysStorageError> {
        let identifier = conv_contract_identifier(identifier);
        let key = conv_contract_key(key);

        let result = self
            .0
            .get(identifier, &key)
            .map_err(|_| DeoxysStorageError::StorageRetrievalError(StorageType::Contract))?;

        Ok(result)
    }
}

impl<'a> ContractTrieHandler<'a> {
    fn root(&mut self, block_number: u64) -> Result<Felt, DeoxysStorageError> {
        self.0
            .commit(BasicId::new(block_number))
            .map_err(|_| DeoxysStorageError::TrieRootError(StorageType::Contract))?;

        let root_hash = self
            .0
            .root_hash(bonsai_identifier::CONTRACT)
            .map_err(|_| DeoxysStorageError::TrieRootError(StorageType::Contract))?;

        Ok(root_hash)
    }
}

impl<'a> TrieHandler<ContractAddress, StorageKey, StarkFelt> for ContractStorageTrieHandler<'a> {
    fn insert(
        &mut self,
        identifier: &ContractAddress,
        key: &StorageKey,
        value: StarkFelt,
    ) -> Result<(), DeoxysStorageError> {
        let identifier = conv_contract_identifier(&identifier);
        let key = conv_contract_storage_key(key);
        let value = conv_contract_value(value);

        self.0
            .insert(identifier, &key, &value)
            .map_err(|_| DeoxysStorageError::StorageInsertionError(StorageType::ContractStorage))?;

        Ok(())
    }

    fn get(&self, identifier: &ContractAddress, key: &StorageKey) -> Result<Option<Felt>, DeoxysStorageError> {
        let identifier = conv_contract_identifier(identifier);
        let key = conv_contract_storage_key(key);

        let result = self
            .0
            .get(identifier, &key)
            .map_err(|_| DeoxysStorageError::StorageRetrievalError(StorageType::ContractStorage))?;

        Ok(result)
    }
}

impl<'a> ContractStorageTrieHandler<'a> {
    fn root(&mut self, block_number: u64, identifier: &ContractAddress) -> Result<Felt, DeoxysStorageError> {
        self.0
            .commit(BasicId::new(block_number))
            .map_err(|_| DeoxysStorageError::TrieRootError(StorageType::ContractStorage))?;

        let identifier = conv_contract_identifier(identifier);
        let root_hash = self
            .0
            .root_hash(identifier)
            .map_err(|_| DeoxysStorageError::TrieRootError(StorageType::ContractStorage))?;

        Ok(root_hash)
    }
}

fn conv_contract_identifier(identifier: &ContractAddress) -> &[u8] {
    identifier.0.0.0.as_bytes_ref()
}

fn conv_contract_key(key: &ContractAddress) -> BitVec<u8, Msb0> {
    key.0.0.0.as_bits().to_owned()
}

fn conv_contract_storage_key(key: &StorageKey) -> BitVec<u8, Msb0> {
    key.0.0.0.as_bits().to_owned()
}

fn conv_contract_value(value: StarkFelt) -> Felt {
    Felt::from_bytes_be(&value.0)
}
