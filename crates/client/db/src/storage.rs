use std::fmt::Display;
use std::sync::MutexGuard;

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
    #[error("failed to initialize trie for {0}")]
    TrieInitError(StorageType),
    #[error("failed to compute trie root for {0}")]
    TrieRootError(StorageType),
    #[error("failed to commit to {0}")]
    TrieCommitError(StorageType),
}

mod bonsai_identifier {
    pub const CONTRACT: &[u8] = "0xcontract".as_bytes();
    pub const CLASS: &[u8] = "0xclass".as_bytes();
    pub const TRANSACTION: &[u8] = "0xtransaction".as_bytes();
    pub const EVENT: &[u8] = "0xevent".as_bytes();
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

impl<'a> ContractTrieHandler<'a> {
    pub fn insert(&mut self, key: &ContractAddress, value: Felt) -> Result<(), DeoxysStorageError> {
        let key = conv_contract_key(key);

        self.0.insert(bonsai_identifier::CONTRACT, &key, &value).expect("show not fail lol");

        Ok(())
    }

    pub fn get(&self, key: &ContractAddress) -> Result<Option<Felt>, DeoxysStorageError> {
        let key = conv_contract_key(key);

        let result = self
            .0
            .get(bonsai_identifier::CONTRACT, &key)
            .map_err(|_| DeoxysStorageError::StorageRetrievalError(StorageType::Contract))?;

        Ok(result)
    }

    pub fn commit(&mut self, block_number: u64) -> Result<(), DeoxysStorageError> {
        self.0
            .commit(BasicId::new(block_number))
            .map_err(|_| DeoxysStorageError::TrieCommitError(StorageType::Contract))?;

        Ok(())
    }

    pub fn init(&mut self) -> Result<(), DeoxysStorageError> {
        self.0
            .init_tree(bonsai_identifier::CONTRACT)
            .map_err(|_| DeoxysStorageError::TrieInitError(StorageType::Contract))?;

        Ok(())
    }

    pub fn root(&mut self) -> Result<Felt, DeoxysStorageError> {
        let root_hash = self
            .0
            .root_hash(bonsai_identifier::CONTRACT)
            .map_err(|_| DeoxysStorageError::TrieRootError(StorageType::Contract))?;

        Ok(root_hash)
    }
}

impl<'a> ContractStorageTrieHandler<'a> {
    pub fn insert(
        &mut self,
        identifier: &ContractAddress,
        key: &StorageKey,
        value: StarkFelt,
    ) -> Result<(), DeoxysStorageError> {
        let identifier = conv_contract_identifier(identifier);
        let key = conv_contract_storage_key(key);
        let value = conv_contract_value(value);

        self.0.insert(identifier, &key, &value).unwrap();
        Ok(())
    }

    pub fn get(&self, identifier: &ContractAddress, key: &StorageKey) -> Result<Option<Felt>, DeoxysStorageError> {
        let identifier = conv_contract_identifier(identifier);
        let key = conv_contract_storage_key(key);

        let result = self
            .0
            .get(identifier, &key)
            .map_err(|_| DeoxysStorageError::StorageRetrievalError(StorageType::ContractStorage))?;

        Ok(result)
    }

    pub fn commit(&mut self, block_number: u64) -> Result<(), DeoxysStorageError> {
        self.0
            .commit(BasicId::new(block_number))
            .map_err(|_| DeoxysStorageError::TrieCommitError(StorageType::ContractStorage))?;

        Ok(())
    }

    pub fn init(&mut self, identifier: &ContractAddress) -> Result<(), DeoxysStorageError> {
        let identifier = conv_contract_identifier(identifier);
        self.0.init_tree(identifier).unwrap();

        Ok(())
    }

    pub fn root(&mut self, identifier: &ContractAddress) -> Result<Felt, DeoxysStorageError> {
        let identifier = conv_contract_identifier(identifier);
        let root_hash = self.0.root_hash(identifier).unwrap();

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
