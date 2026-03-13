//! Wallet account model — organise addresses under named accounts/labels.
//!
//! Bitcoin Core supports multiple accounts (historically) and labels (modern)
//! for grouping addresses. This module provides the corresponding data
//! structures and CRUD operations.

use std::collections::HashMap;

use crate::error::WalletError;

/// A named wallet account that groups a set of addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletAccount {
    /// Human-readable account name (unique within the wallet).
    pub name: String,
    /// Addresses belonging to this account.
    pub addresses: Vec<String>,
}

impl WalletAccount {
    /// Create a new empty account with the given name.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            addresses: Vec::new(),
        }
    }

    /// Add an address to this account if it is not already present.
    pub fn add_address(&mut self, addr: &str) {
        if !self.addresses.contains(&addr.to_string()) {
            self.addresses.push(addr.to_string());
        }
    }

    /// Remove an address from this account.
    pub fn remove_address(&mut self, addr: &str) {
        self.addresses.retain(|a| a != addr);
    }

    /// Check whether this account contains the given address.
    pub fn contains_address(&self, addr: &str) -> bool {
        self.addresses.iter().any(|a| a == addr)
    }
}

/// Manager for multiple wallet accounts.
///
/// Provides CRUD operations matching Bitcoin Core's account/label system.
#[derive(Debug, Clone)]
pub struct AccountManager {
    /// Accounts keyed by name.
    accounts: HashMap<String, WalletAccount>,
}

impl AccountManager {
    /// Create a new account manager with a default (empty-string) account.
    pub fn new() -> Self {
        let mut accounts = HashMap::new();
        // Bitcoin Core always has a default account with name ""
        accounts.insert(String::new(), WalletAccount::new(""));
        Self { accounts }
    }

    /// Create a new named account. Returns an error if the name is already in use.
    pub fn create_account(&mut self, name: &str) -> Result<&WalletAccount, WalletError> {
        if self.accounts.contains_key(name) {
            return Err(WalletError::InvalidAddress(format!(
                "account already exists: '{name}'"
            )));
        }
        self.accounts
            .insert(name.to_string(), WalletAccount::new(name));
        Ok(self.accounts.get(name).unwrap())
    }

    /// Get an account by name.
    pub fn get_account(&self, name: &str) -> Option<&WalletAccount> {
        self.accounts.get(name)
    }

    /// Get a mutable reference to an account by name.
    pub fn get_account_mut(&mut self, name: &str) -> Option<&mut WalletAccount> {
        self.accounts.get_mut(name)
    }

    /// List all accounts, sorted by name.
    pub fn list_accounts(&self) -> Vec<&WalletAccount> {
        let mut accts: Vec<_> = self.accounts.values().collect();
        accts.sort_by_key(|a| &a.name);
        accts
    }

    /// Delete an account by name. The default account ("") cannot be deleted.
    pub fn delete_account(&mut self, name: &str) -> Result<(), WalletError> {
        if name.is_empty() {
            return Err(WalletError::InvalidAddress(
                "cannot delete the default account".into(),
            ));
        }
        if self.accounts.remove(name).is_none() {
            return Err(WalletError::InvalidAddress(format!(
                "account not found: '{name}'"
            )));
        }
        Ok(())
    }

    /// Assign an address to an account, removing it from any previous account.
    pub fn assign_address(&mut self, account_name: &str, addr: &str) -> Result<(), WalletError> {
        if !self.accounts.contains_key(account_name) {
            return Err(WalletError::InvalidAddress(format!(
                "account not found: '{account_name}'"
            )));
        }
        // Remove from any existing account
        for acct in self.accounts.values_mut() {
            acct.remove_address(addr);
        }
        // Add to the target account
        self.accounts
            .get_mut(account_name)
            .unwrap()
            .add_address(addr);
        Ok(())
    }

    /// Find which account an address belongs to.
    pub fn account_for_address(&self, addr: &str) -> Option<&str> {
        for acct in self.accounts.values() {
            if acct.contains_address(addr) {
                return Some(&acct.name);
            }
        }
        None
    }
}

impl Default for AccountManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_account_exists() {
        let mgr = AccountManager::new();
        assert!(mgr.get_account("").is_some());
        assert_eq!(mgr.list_accounts().len(), 1);
    }

    #[test]
    fn create_and_list_accounts() {
        let mut mgr = AccountManager::new();
        mgr.create_account("savings").unwrap();
        mgr.create_account("trading").unwrap();
        let list = mgr.list_accounts();
        assert_eq!(list.len(), 3); // default + savings + trading
        // Sorted by name: "" < "savings" < "trading"
        assert_eq!(list[0].name, "");
        assert_eq!(list[1].name, "savings");
        assert_eq!(list[2].name, "trading");
    }

    #[test]
    fn create_duplicate_account_fails() {
        let mut mgr = AccountManager::new();
        mgr.create_account("test").unwrap();
        assert!(mgr.create_account("test").is_err());
    }

    #[test]
    fn delete_account() {
        let mut mgr = AccountManager::new();
        mgr.create_account("temp").unwrap();
        assert_eq!(mgr.list_accounts().len(), 2);
        mgr.delete_account("temp").unwrap();
        assert_eq!(mgr.list_accounts().len(), 1);
    }

    #[test]
    fn delete_default_account_fails() {
        let mut mgr = AccountManager::new();
        assert!(mgr.delete_account("").is_err());
    }

    #[test]
    fn delete_nonexistent_account_fails() {
        let mut mgr = AccountManager::new();
        assert!(mgr.delete_account("nope").is_err());
    }

    #[test]
    fn assign_and_find_address() {
        let mut mgr = AccountManager::new();
        mgr.create_account("savings").unwrap();
        mgr.assign_address("savings", "bc1qtest123").unwrap();
        assert_eq!(
            mgr.account_for_address("bc1qtest123"),
            Some("savings")
        );
        let acct = mgr.get_account("savings").unwrap();
        assert!(acct.contains_address("bc1qtest123"));
    }

    #[test]
    fn assign_address_moves_between_accounts() {
        let mut mgr = AccountManager::new();
        mgr.create_account("a").unwrap();
        mgr.create_account("b").unwrap();
        mgr.assign_address("a", "addr1").unwrap();
        assert_eq!(mgr.account_for_address("addr1"), Some("a"));
        // Move to account "b"
        mgr.assign_address("b", "addr1").unwrap();
        assert_eq!(mgr.account_for_address("addr1"), Some("b"));
        assert!(!mgr.get_account("a").unwrap().contains_address("addr1"));
    }

    #[test]
    fn assign_to_nonexistent_account_fails() {
        let mut mgr = AccountManager::new();
        assert!(mgr.assign_address("nope", "addr1").is_err());
    }

    #[test]
    fn wallet_account_no_duplicate_addresses() {
        let mut acct = WalletAccount::new("test");
        acct.add_address("addr1");
        acct.add_address("addr1");
        assert_eq!(acct.addresses.len(), 1);
    }

    #[test]
    fn account_for_unknown_address() {
        let mgr = AccountManager::new();
        assert!(mgr.account_for_address("unknown").is_none());
    }
}
