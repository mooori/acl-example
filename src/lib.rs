// TODO
// - after discussing events approach, log events in all fns modifying Acl state
//   - Ideas for something more 'elegant' than `&'static str` to avoid allocs?
// - discuss: should enumeration be opt-in or opt-out?

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{TreeMap, UnorderedSet};
use near_sdk::serde::Serialize;
use near_sdk::serde_json;
use near_sdk::{env, near_bindgen, AccountId, BorshStorageKey};

/// Roles are represented by enum variants.
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize, Serialize,
)]
#[serde(crate = "near_sdk::serde")]
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
    R: Copy + Ord + BorshDeserialize + BorshSerialize + Serialize,
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
    /// internal storage and modifications are persisted when wrapped in a
    /// function that triggers writing to storage. See [returning derived data].
    ///
    /// To retrieve a set that will be saved to storage in either case, use
    /// `[get_or_insert_admins_set]`.
    ///
    /// [returning derived data]: https://www.near-sdk.io/contract-interface/contract-mutability#returning-derived-data
    pub fn get_admins_set(&self, role: R) -> UnorderedSet<AccountId> {
        match self.admins.get(&role) {
            Some(set) => set,
            None => Self::new_admins_set(role),
        }
    }

    /// Similar to [`get_admins_set`], but inserting newly initialized sets into
    /// the data structure written to storage. Use this method if modifications
    /// to the returned set need to be persisted.
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

    /// Copies the `AccountId`s which are admin for `role`.
    pub fn get_admins(&self, role: R) -> Vec<AccountId> {
        self.get_admins_set(role).to_vec()
    }

    /// Returns a `bool` indicating if `account_id` is an admin for `role`.
    pub fn is_admin(&self, role: R, account_id: &AccountId) -> bool {
        self.get_admins_set(role).contains(account_id)
    }

    /// Adds `account_id` to the set of admins for `role`, given that the caller
    /// is an admin for `role`. Returns `Some(bool)` indicating whether
    /// `account_id` was newly added to the set of admins for `role`.
    ///
    /// If the caller is not and admin for `role`, `account_id` is not added to
    /// the set of admins and `None` is returned.
    pub fn add_admin(&mut self, role: R, account_id: &AccountId) -> Option<bool> {
        // TODO discuss: two lookups happen here: is_admin() + add_admin_unchecked().
        // What's more important: DRY+readability or micro optimization (avoid methods
        // to bring the number of lookups down to one)? Same at other places which
        // call `is_admin()` before doing a modifications.
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        Some(self.add_admin_unchecked(role, account_id))
    }

    /// Adds `account_id` to the set of admins for `role` __without__ checking
    /// if the caller is and admin for `role`.
    ///
    /// Returns whether `account_id` was newly added to the set of admins for
    /// `role`.
    pub fn add_admin_unchecked(&mut self, role: R, account_id: &AccountId) -> bool {
        let result = self.get_or_insert_admins_set(role).insert(account_id);

        // TODO create fn/macro to simplify emitting events
        let event_ser = {
            let event = AclEvent::new(
                AclEventId::AdminAdded,
                AclEventMetadata {
                    role,
                    account_id: account_id.clone(),
                    predecessor: env::predecessor_account_id(),
                },
            );
            serde_json::to_string(&event)
                .unwrap_or_else(|_| env::panic_str("Failed to serialize Event"))
        };
        env::log_str(&event_ser);

        result
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

    fn new_grants_set(account_id: &AccountId) -> UnorderedSet<R> {
        UnorderedSet::new(ACLStorageKeys::GrantsPerAccountId {
            account_id_hash: env::sha256(account_id.as_bytes()),
        })
    }

    /// Returns the set of roles that have been granted to `account_id`.
    ///
    /// The returned set may not be persisted to storage, in line with
    /// [`get_admins_set`]. To be certain that the set will be stored, use
    /// [`get_or_insert_grants_set`].
    fn get_grants_set(&self, account_id: &AccountId) -> UnorderedSet<R> {
        match self.grants.get(account_id) {
            Some(set) => set,
            None => Self::new_grants_set(account_id),
        }
    }

    /// Similar to [`get_grants_set`], but inserting newly initialized sets into
    /// the data structure written to storage. Use this method if modifications
    /// to the returned set need to be persisted.
    fn get_or_insert_grants_set(&mut self, account_id: &AccountId) -> UnorderedSet<R> {
        match self.grants.get(account_id) {
            Some(set) => set,
            None => {
                let set = Self::new_grants_set(account_id);
                self.grants.insert(account_id, &set);
                set
            }
        }
    }

    /// Copies the roles which were granted to `account_id`.
    fn get_grants(&self, account_id: &AccountId) -> Vec<R> {
        self.get_grants_set(account_id).to_vec()
    }

    /// Grants `role` to `account_id`, given that the caller is an admin for
    /// `role`. Returns `Some(bool)` indicating wheter `role` was newly granted
    /// to `account_id`.
    ///
    /// If the caller is not an admin for `role`, `account_id` is not granted
    /// the role and `None` is returned.
    fn grant_role(&mut self, role: R, account_id: &AccountId) -> Option<bool> {
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        Some(self.grant_role_unchecked(role, account_id))
    }

    /// Grants `role` to `account_id` __without__ checking if the caller is and
    /// admin for `role`.
    ///
    /// Returns whether `role` was newly granted to `account_id`.
    fn grant_role_unchecked(&mut self, role: R, account_id: &AccountId) -> bool {
        self.get_or_insert_grants_set(account_id).insert(&role)
    }

    /// Revoke `role` from `account_id`. If the caller is an admin for `role`,
    /// it returns `Some(bool)` indicating whether `account_id` was a grantee of
    /// `role`.
    ///
    /// If the caller is not an admin for `role`, it returns `None` and the set
    /// of grants is not modified.
    fn revoke_role(&mut self, role: R, account_id: &AccountId) -> Option<bool> {
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        // If the set is empty, the modifications here a noops and we don't mind
        // _not_ persisting them. So no need for `get_or_insert_grants_set`.
        let mut set = self.get_grants_set(account_id);
        Some(set.remove(&role))
    }

    /// Removes `role` from the set of roles granted to `account_id`. Returns
    /// whether the role was previously granted to `account_id`.
    fn renounce_role(&mut self, role: R) -> bool {
        // If the set is empty, the modifications here a noops and we don't mind
        // _not_ persisting them. So no need for `get_or_insert_admins_set`.
        self.get_grants_set(&env::predecessor_account_id())
            .remove(&role)
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

// TODO probably should be the near-plugins ACL standard (if we define one)
const EVENT_STANDARD: &str = "nep279";
const EVENT_VERSION: &str = "1.0.0";

/// Represents a [NEP-297] event.
///
/// Using `'static &str` where possible to avoid allocations (there's only a
/// small set of possible values for the corresponding fields).
///
/// [NEP-297]: https://nomicon.io/Standards/EventsFormat

// TODO try using lifetime `'a` instead of `'static`.
// TODO allow users emitting custom data together with events (in later version)
#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
struct AclEvent<R> {
    standard: &'static str,
    version: &'static str,
    event: &'static str,
    data: AclEventMetadata<R>,
}

impl<R> AclEvent<R> {
    fn new(acl_event_id: AclEventId, data: AclEventMetadata<R>) -> Self {
        Self {
            standard: EVENT_STANDARD,
            version: EVENT_VERSION,
            event: acl_event_id.name(),
            data,
        }
    }
}

/// Events resulting from ACL actions.
#[derive(Copy, Clone)]
enum AclEventId {
    AdminAdded,
    AdminRemoved,
    RoleGranted,
    RoleRevoked,
    RoleRenounced,
}

impl AclEventId {
    /// Returns the name to be used in the `event` field when formatting
    /// according to NEP-297.
    ///
    /// Returning `&'static str` to avoid allocations when emitting events.
    fn name(self) -> &'static str {
        // TODO let user change event prefix `acl_`
        match self {
            Self::AdminAdded => "acl_admin_added",
            Self::AdminRemoved => "acl_admin_removed",
            Self::RoleGranted => "acl_role_granted",
            Self::RoleRevoked => "acl_role_revoked",
            Self::RoleRenounced => "acl_role_renounced",
        }
    }
}

/// Metadata emitted in NEP-297 event field `data`.

// TODO use references to `AccountId` (avoid cloning); if it works with serde.
// If `Deserialize` must be derived, probably won't work (out of the box).
#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
struct AclEventMetadata<R> {
    /// The role related to the event.
    role: R,
    /// The account whose permissions are affected.
    account_id: AccountId,
    /// The account which originated the contract call.
    predecessor: AccountId,
}
