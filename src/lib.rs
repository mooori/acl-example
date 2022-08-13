// TODO
// - add event logs
// - discuss: should enumeration be opt-in or opt-out?

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{TreeMap, UnorderedSet};
use near_sdk::{env, near_bindgen, AccountId, BorshStorageKey};

/// Roles are represented by enum variants.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize)]
enum Role {
    L1,
    L2,
    L3,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Counter {
    counter: u64,
    acl: Acl<Role>,
}

#[near_bindgen]
impl Counter {
    #[init]
    pub fn new() -> Self {
        let mut contract = Self {
            counter: 0,
            acl: Acl::new(),
        };

        let caller = env::predecessor_account_id();
        contract.acl.add_admin_unchecked(Role::L1, &caller);
        contract.acl.add_admin_unchecked(Role::L2, &caller);
        contract.acl.add_admin_unchecked(Role::L3, &caller);

        contract
    }
}

/// Acl manages admins and grants for roles. Roles are represented by variants
/// of enum `R`.
// TODO enable opt-out of enumerable collections (efficiency)
#[derive(BorshDeserialize, BorshSerialize)]
struct Acl<R> {
    /// Stores the set of `AccountId`s which are admins for each role.
    admins: TreeMap<R, UnorderedSet<AccountId>>,

    /// Stores the set of roles which have been granted to accounts.
    // TODO use a bit field instead of `UnorderedSet`. To make testing if an
    // account has at least one of many roles more efficient.
    grants: TreeMap<AccountId, UnorderedSet<R>>,
}

impl<R> Acl<R>
where
    R: Copy + Ord + BorshDeserialize + BorshSerialize,
{
    pub fn new() -> Self {
        Self {
            admins: TreeMap::new(ACLStorageKeys::Admins),
            grants: TreeMap::new(ACLStorageKeys::Grants),
        }
    }

    fn new_admins_set(role: R) -> UnorderedSet<AccountId> {
        UnorderedSet::new(ACLStorageKeys::AdminsPerRole {
            role_hash: role
                .try_to_vec()
                .unwrap_or_else(|_| env::panic_str("Failed to serialize Role variant")),
        })
    }

    /// For roles that don't have an admin, a newly initialized empty set is
    /// returned. This set is _not_ a member of the internal data structures and
    /// it will _not_ be written to storage. In that case, any changes made to
    /// the returned set will be lost.
    ///
    /// However, if there are admins for `role`, the returned set is a member of
    /// internal storage and modifications will be persisted.
    ///
    /// To retrieve a set that will be saved to storage in either case, use
    /// `[get_or_insert_admins_set]`.
    pub fn get_admins_set(&self, role: R) -> UnorderedSet<AccountId> {
        match self.admins.get(&role) {
            Some(set) => set,
            None => Self::new_admins_set(role),
        }
    }

    /// Similar to [`get_admins_set`], but inserting newly initialized sets into
    /// the data structure written to storage. Use this method if modifications
    /// to the returned set need to persisted.
    fn get_or_insert_admins_set(&mut self, role: R) -> UnorderedSet<AccountId> {
        match self.admins.get(&role) {
            Some(set) => set,
            None => {
                let set = Self::new_admins_set(role);
                self.admins.insert(&role, &set);
                set
            }
        }
    }

    /// Copies the `AccountId`s.
    pub fn get_admins(&self, role: R) -> Vec<AccountId> {
        self.get_admins_set(role).to_vec()
    }

    /// Returns a `bool` indicating if `account_id` is an admin for `role`.
    pub fn is_admin(&self, role: R, account_id: &AccountId) -> bool {
        self.get_admins_set(role).contains(account_id)
    }

    /// Adds `account_id` to the set of admins for `role`, given that the caller
    /// is an admin for `role`. Returns `Some(true)` if `account_id` was _not_
    /// yet present in the set, otherwise `Some(false)`.
    ///
    /// If the caller is not and admin for `role`, `account_id` is not added to
    /// the set of admins and `None` is returned.
    pub fn add_admin(&mut self, role: R, account_id: &AccountId) -> Option<bool> {
        // TODO discuss: two lookups happen here: is_admin(), add_admin_unchecked().
        // What's more important: DRY+readability or micro optimization (avoid methods
        // to bring the number of lookups down to one)? Same at other places.
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        Some(self.add_admin_unchecked(role, account_id))
    }

    /// Adds `account_id` to the set of admins for `role` __without__ checking
    /// if the caller is and admin for `role`.
    pub fn add_admin_unchecked(&mut self, role: R, account_id: &AccountId) -> bool {
        self.get_or_insert_admins_set(role).insert(account_id)
    }

    /// Remove an `account_id` from the set of admins for `role`. If the caller
    /// is an admin for `role`, it returns `Some<bool>` indicating whether
    /// `account_id` was an admin.
    ///
    /// If the caller is not an admin for `role`, it returns `None` and the set
    /// of admins is not modified.
    fn revoke_admin(&mut self, role: R, account_id: &AccountId) -> Option<bool> {
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        // If the set is empty, the modifications here a noops and we don't mind
        // _not_ persisting them. So no need for `get_or_insert_admins_set`.
        let mut set = self.get_admins_set(role);
        Some(set.remove(account_id))
    }

    /// Removes the calling account from the set of admins for `role`. Returns
    /// whether the caller was an admin for `role`.
    fn renounce_admin(&mut self, role: R) -> bool {
        // If the set is empty, the modifications here a noops and we don't mind
        // _not_ persisting them. So no need for `get_or_insert_admins_set`.
        self.get_admins_set(role)
            .remove(&env::predecessor_account_id())
    }
}

// TODO discuss:
// - Optionally allowing user to set storage keys is to avoid collisions?
// - Still needed if using an enum (which should avoid collisions)?
#[derive(BorshStorageKey, BorshSerialize)]
pub enum ACLStorageKeys {
    Admins,
    AdminsPerRole { role_hash: Vec<u8> },
    Grants,
    GrantsPerAccountId { account_id_hash: Vec<u8> },
}
