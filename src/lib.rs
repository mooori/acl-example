// TODO
// - after discussing events approach, log events in all fns modifying Acl state
//   - Ideas for something more 'elegant' than `&'static str` to avoid allocs?
// - discuss: should enumeration be opt-in or opt-out?

use bitflags::bitflags;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedMap;
use near_sdk::serde::Serialize;
use near_sdk::{env, near_bindgen, AccountId, BorshStorageKey};

/// Roles are represented by enum variants.
#[derive(Copy, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize)]
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
    acl: Acl,
}

#[near_bindgen]
impl Counter {
    #[init]
    pub fn new() -> Self {
        let contract = Self {
            counter: 0,
            acl: Acl::new(),
        };

        let _caller = env::predecessor_account_id();
        /*
        contract.acl.add_admin_unchecked(Role::L1, &caller);
        contract.acl.add_admin_unchecked(Role::L2, &caller);
        contract.acl.add_admin_unchecked(Role::L3, &caller);
        */

        contract
    }
}

/// Represents admin permissions for roles. Variant `Super` grants global admin
/// permissions, each following variant grants admin permissions for the `Role`
/// with the corresponding name.
#[derive(Copy, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
enum AclAdmin {
    Super,
    L1,
    L2,
    L3,
}

bitflags! {
    /// Flags that represent permissions in a bitmask.
    ///
    /// If a flag's binary value is `1 << n` with even `n` it represents an
    /// `AclAdmin` role. Otherwise (`n` is odd), the flag represents a regular
    /// `Role`.
    ///
    /// Bitmasks allow efficiently checking for multiple permissions.
    #[derive(BorshDeserialize, BorshSerialize)]
    struct AclPermissions: u128 {
        const SUPER_ADMIN = 0b00000001; // 01u128 == 1 << 0
        const L1 = 0b00000010;         // 02u128 == 1 << 1
        const L1_ADMIN = 0b00000100;    // 04u128 == 1 << 2
        const L2 = 0b00001000;         // 08u128 == 1 << 3
        const L2_ADMIN = 0b00010000;    // 16u128 == 1 << 4
        const L3 = 0b00100000;         // 32u128 == 1 << 5
        const L3_ADMIN = 0b01000000;    // 64u128 == 1 << 6
    }
}

const MAX_BITFLAG_SHIFT: u8 = 127; // `AclPermissions` is u128

#[inline]
fn assert(condition: bool, error: &str) {
    if !condition {
        env::panic_str(error);
    }
}

impl From<Role> for AclPermissions {
    fn from(value: Role) -> Self {
        // `+1` since flags for `Role` have a bit shifted by an odd number.
        let shift = (value as u8 * 2) + 1;
        assert(shift <= MAX_BITFLAG_SHIFT, "Role is out of bounds");
        AclPermissions::from_bits(1u128 << shift)
            .unwrap_or_else(|| env::panic_str("Failed to convert Role"))
    }
}

impl From<AclAdmin> for AclPermissions {
    fn from(value: AclAdmin) -> Self {
        // Flags for `AclAdmin` have a bit shifted by an even number.
        let shift = value as u8 * 2;
        assert(shift <= MAX_BITFLAG_SHIFT, "AclAdmin is out of bounds");
        AclPermissions::from_bits(1u128 << shift)
            .unwrap_or_else(|| env::panic_str("Failed to convert AclAdmin"))
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct Acl {
    permissions: UnorderedMap<AccountId, AclPermissions>,
}

impl Acl {
    fn new() -> Self {
        Self {
            permissions: UnorderedMap::new(ACLStorageKeys::Permissions),
        }
    }

    /// For an `account_id` which is not stored internally, a newly initialized
    /// empty `AclPermissions` bitmask is returned. It will _not_ be written to
    /// storage since it is not a member of any internal data structure. Changes
    /// made to that value are lost.
    ///
    /// However, if `account_id` is already stored internally, changes made to
    /// the returned value a persisted if wrapped in a function that triggers
    /// writting to storage. See [returning derived data].
    ///
    /// To retrieve a value that will be saved to storage in either case, use
    /// [`get_or_insert_permissions`].
    ///
    /// [returning derived data]: https://www.near-sdk.io/contract-interface/contract-mutability#returning-derived-data
    fn get_permissions(&self, account_id: &AccountId) -> AclPermissions {
        match self.permissions.get(account_id) {
            Some(permissions) => permissions,
            None => AclPermissions::empty(),
        }
    }

    /// Similar to [`get_permissions`], but inserting a newly initialized
    /// `AclPermissions` bitmask into the data structure written to storage. Use
    /// this method if modifications to the returned value need to be persisted.
    fn get_or_insert_permissions(&mut self, account_id: &AccountId) -> AclPermissions {
        match self.permissions.get(account_id) {
            Some(permissions) => permissions,
            None => {
                let permissions = AclPermissions::empty();
                self.permissions.insert(account_id, &permissions);
                permissions
            }
        }
    }
}

// TODO discuss:
// - Optionally allowing user to set storage keys is to avoid collisions?
// - Still needed if using an enum (which should avoid collisions)?
#[derive(BorshStorageKey, BorshSerialize)]
pub enum ACLStorageKeys {
    Permissions,
}
