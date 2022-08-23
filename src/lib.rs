// TODO
// - after discussing events approach, log events in all fns modifying Acl state
//   - Ideas for something more 'elegant' than `&'static str` to avoid allocs?
// - discuss: should enumeration be opt-in or opt-out?

use bitflags::bitflags;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedMap;
use near_sdk::serde::Serialize;
use near_sdk::serde_json;
use near_sdk::{env, near_bindgen, AccountId, BorshStorageKey};

/// Roles are represented by enum variants.
#[derive(Copy, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
#[repr(u8)]
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

/// Represents admin permissions for roles. Variant `Super` grants global admin
/// permissions, each following variant grants admin permissions for the `Role`
/// with the corresponding name.
#[derive(Copy, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
#[repr(u8)]
enum AclAdmin {
    Super,
    L1,
    L2,
    L3,
}

impl From<Role> for AclAdmin {
    fn from(value: Role) -> Self {
        match value {
            Role::L1 => AclAdmin::L1,
            Role::L2 => AclAdmin::L2,
            Role::L3 => AclAdmin::L3,
        }
    }
}

impl Role {
    /// Returns the `AclAdmin` variant responsible for a `Role`.
    fn admin(self) -> AclAdmin {
        AclAdmin::from(self)
    }
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
        const L1 = 0b00000010;          // 02u128 == 1 << 1
        const L1_ADMIN = 0b00000100;    // 04u128 == 1 << 2
        const L2 = 0b00001000;          // 08u128 == 1 << 3
        const L2_ADMIN = 0b00010000;    // 16u128 == 1 << 4
        const L3 = 0b00100000;          // 32u128 == 1 << 5
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

    /// Returns a `bool` indicating if `account_id` is an admin for `role`.
    fn is_admin(&self, role: Role, account_id: &AccountId) -> bool {
        self.get_permissions(account_id)
            .contains(role.admin().into())
    }

    /// Grants admin permissions for `role` to `account_id`, __without__
    /// checking permissions of the predecessor.
    ///
    /// Returns whether `account_id` was newly added to the admins for `role`.
    fn add_admin_unchecked(&mut self, role: Role, account_id: &AccountId) -> bool {
        let flag: AclPermissions = role.admin().into();
        let mut permissions = self.get_or_insert_permissions(account_id);
        let newly_added = !permissions.contains(flag);
        if newly_added {
            permissions.insert(flag);
            AclEvent::new_from_env(AclEventId::AdminAdded, role, account_id.clone()).emit();
        }
        newly_added
    }
}

// TODO discuss:
// - Optionally allowing user to set storage keys is to avoid collisions?
// - Still needed if using an enum (which should avoid collisions)?
#[derive(BorshStorageKey, BorshSerialize)]
pub enum ACLStorageKeys {
    Permissions,
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

impl<R> AclEvent<R>
where
    R: Serialize,
{
    fn new(id: AclEventId, data: AclEventMetadata<R>) -> Self {
        Self {
            standard: EVENT_STANDARD,
            version: EVENT_VERSION,
            event: id.name(),
            data,
        }
    }

    /// Constructor which reads predecessor's account id from the current
    /// environment. Parameters `role` and `account_id` are passed on to
    /// [`AclEventMetadata`].
    fn new_from_env(id: AclEventId, role: R, account_id: AccountId) -> Self {
        Self {
            standard: EVENT_STANDARD,
            version: EVENT_VERSION,
            event: id.name(),
            data: AclEventMetadata {
                role,
                account_id,
                predecessor: env::predecessor_account_id(),
            },
        }
    }

    /// Emits the event by logging to the current environment.
    fn emit(&self) {
        let ser = serde_json::to_string(self)
            .unwrap_or_else(|_| env::panic_str("Failed to serialize AclEvent"));
        env::log_str(&ser)
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
