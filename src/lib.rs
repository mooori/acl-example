// TODO
// - add event logs
// - add init of `acl_*` struct fields in contracts `#[init]` resp. `Default`
// - disuss: should enumeration be opt-in or opt-out?

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{TreeMap, UnorderedSet, Vector};
use near_sdk::{env, near_bindgen, AccountId, BorshStorageKey};
use strum::IntoEnumIterator;

/// Roles are represented by enum variants.
///
/// This enum will be used to index a `near_sdk::collections::Vector` which
/// is indexed by `u64`, hence `repr(u64)`.
#[derive(Copy, Clone, BorshSerialize, strum::EnumIter)]
#[repr(u64)]
enum Role {
    L1,
    L2,
    L3,
}

impl Into<u64> for Role {
    fn into(self) -> u64 {
        self as u64
    }
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Counter {
    counter: u64,

    // # Motivation for `ACLRoleAdmins` and `ACLRoleGrants`
    //
    // Offload as much as possible to separate types, to be less intrusive on
    // the contract itself and to facilitate testing.
    //
    // Separate checks of permission from modification of internal data:
    // `Contract::grant_role()` just checks permissions and then calls
    // `ACLRoleGrants::grant_role()` which adds grant to its internal data. This
    // separation might facilitate testing and maintenance.
    //
    // Makes sense?
    acl: Acl<Role>,
}

#[near_bindgen]
impl Counter {
    #[init]
    pub fn new() -> Self {
        let mut acl = Acl::new();
        let caller = env::predecessor_account_id();
        for role in Role::iter() {
            acl.add_admin_unchecked(role, &caller);
        }

        Self { counter: 0, acl }
    }
}

// TODO enable opt-out of enumerable collections (efficiency)
#[derive(BorshDeserialize, BorshSerialize)]
struct Acl<R> {
    /// Stores the set of `AccountId`s which are admins for roles (the variants
    /// of `R`).
    ///
    /// Invariant: Let `r` be a variant of `Role`, then
    /// `admins[Into::<u64>::into(role)]` stores the set of admins for role `r`.
    ///
    /// Motivation: without this invariant, `get_admins` would be one of:
    /// ```
    /// // Returning an option if `role` is unitialized.
    /// fn get_admins(&self, role: R) -> Option<UnorderedSet<AccountId>>
    ///
    /// // Taking a mutable reference to store a newly initialized set for `role`.
    /// fn get_admins(&mut self, role: R) -> UnorderesSet<AccountId>
    /// ```
    admins: Vector<UnorderedSet<AccountId>>,
    // TODO get rid of invariant and vector. Instead get_admins_set is private and any modifications of set are not stored.
    /// Stores the set of roles which have been granted to accounts.
    grants: TreeMap<AccountId, UnorderedSet<R>>,
}

impl<R> Acl<R>
where
    R: Copy + Into<u64> + BorshSerialize,
{
    pub fn new() -> Self {
        // Initiate `admins` with an empty set for each variant of `R` to
        // satisfy the invariant of the `admins` field.
        let mut admins = Vector::new(ACLStorageKeys::Admins);
        // TODO avoid enumerate since it might overflow?
        for (i, role) in Role::iter().enumerate() {
            // Ensure Role variants are in range [0, num_variants).
            let i = u64::try_from(i)
                .unwrap_or_else(|_| env::panic_str("Cannot convert iterator index to u64"));
            if Into::<u64>::into(role) != i {
                env::panic_str("Enum cannot be used to index Vector")
            }

            admins.push(&UnorderedSet::new(ACLStorageKeys::AdminsPerRole {
                role_hash: role
                    .try_to_vec()
                    .unwrap_or_else(|_| env::panic_str("Failed to serialize Role variant")),
            }))
        }

        Self {
            admins,
            grants: TreeMap::new(ACLStorageKeys::Grants),
        }
    }

    /// TODO The returned set may not be a member of the data structure saved to
    /// storage. If not, changes to the set will not be persisted.
    ///
    /// To retrieve a set that will be saved to storage, use
    /// `[get_or_insert_admins_set]`.
    pub fn get_admins_set(&self, role: R) -> UnorderedSet<AccountId> {
        match self.admins.get(role.into()) {
            Some(set) => set,
            None => env::panic_str("Invariant violation: missing set of admins for a role"),
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
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        Some(self.add_admin_unchecked(role, account_id))
    }

    /// Adds `account_id` to the set of admins for `role` __without__ checking
    /// if the caller is and admin for `role`.
    pub fn add_admin_unchecked(&mut self, role: R, account_id: &AccountId) -> bool {
        self.get_admins_set(role).insert(account_id)
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
        let mut set = self.get_admins_set(role);
        Some(set.remove(account_id))
    }

    /// Removes the calling account from the set of admins for `role`. Returns
    /// whether the caller was an admin for `role`.
    fn renounce_admin(&mut self, role: R) -> bool {
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
