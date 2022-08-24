// TODO
// - add enumeration; should it be opt-in or opt-out?
// - how to assign `AclAdmin::Super`?
//   - auto-assign to caller of `new` or let developer assign it to accounts?
// - Consider `AclAdmin::Super` before emitting events?
//   - Assume alice.near has `AclPermissons::SUPER_ADMIN | AclPermissions::L1_ADMIN`.
//     When flag L1_ADMIN is removed, alice.near effectively remains admin for
//     L1 via SUPER_ADMIN.

use bitflags::bitflags;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::UnorderedMap;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::serde_json;
use near_sdk::{env, near_bindgen, require, AccountId, PanicOnDefault};

/// Roles are represented by enum variants.
#[derive(Copy, Clone, PartialEq, Eq, BorshDeserialize, BorshSerialize, Deserialize, Serialize)]
#[serde(crate = "near_sdk::serde")]
#[repr(u8)]
pub enum Role {
    L1,
    L2,
    L3,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
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

    // Methods that were decorated with ACL attributes (see README.md).

    pub fn foo2(&self) {
        self.acl
            .check_any(AclPermissions::L2, &env::predecessor_account_id());
    }

    pub fn foo3(&self) {
        self.acl.check_any(
            AclPermissions::L1 | AclPermissions::L2,
            &env::predecessor_account_id(),
        );
    }

    pub fn foo4(&self) {
        self.acl.check_all(
            AclPermissions::L1 | AclPermissions::L3,
            &env::predecessor_account_id(),
        );
    }

    // Some ACL methods should be automatically exposed on the contract:

    pub fn acl_is_admin(&self, role: Role, account_id: &AccountId) -> bool {
        self.acl.is_admin(role, account_id)
    }

    pub fn acl_add_admin(&mut self, role: Role, account_id: &AccountId) -> Option<bool> {
        self.acl.add_admin(role, account_id)
    }

    pub fn acl_revoke_admin(&mut self, role: Role, account_id: &AccountId) -> Option<bool> {
        self.acl.revoke_admin(role, account_id)
    }

    pub fn acl_renounce_admin(&mut self, role: Role) -> bool {
        self.acl.renounce_admin(role)
    }

    pub fn acl_has_role(&self, role: Role, account_id: &AccountId) -> bool {
        self.acl.has_role(role, account_id)
    }

    pub fn acl_grant_role(&mut self, role: Role, account_id: &AccountId) -> Option<bool> {
        self.acl.grant_role(role, account_id)
    }

    pub fn acl_revoke_role(&mut self, role: Role, account_id: &AccountId) -> Option<bool> {
        self.acl.revoke_role(role, account_id)
    }

    pub fn acl_renounce_role(&mut self, role: Role) -> bool {
        self.acl.renounce_role(role)
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

impl From<Role> for AclPermissions {
    fn from(value: Role) -> Self {
        // `+1` since flags for `Role` have a bit shifted by an odd number.
        let shift = (value as u8 * 2) + 1;
        require!(shift <= MAX_BITFLAG_SHIFT, "Role is out of bounds");
        AclPermissions::from_bits(1u128 << shift)
            .unwrap_or_else(|| env::panic_str("Failed to convert Role"))
    }
}

impl From<AclAdmin> for AclPermissions {
    fn from(value: AclAdmin) -> Self {
        // Flags for `AclAdmin` have a bit shifted by an even number.
        let shift = value as u8 * 2;
        require!(shift <= MAX_BITFLAG_SHIFT, "AclAdmin is out of bounds");
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
            // TODO allow devs to specify another prefix
            permissions: UnorderedMap::new(b"_aclp".to_vec()),
        }
    }

    /// Returns the permissions of `account_id`. If there are no permissions
    /// stored for `account_id`, it returns an empty, newly initialized set of
    /// permissions.
    fn get_or_init_permissions(&self, account_id: &AccountId) -> AclPermissions {
        match self.permissions.get(account_id) {
            Some(permissions) => permissions,
            None => AclPermissions::empty(),
        }
    }

    /// Returns a `bool` indicating if `account_id` is an admin for `role`.
    ///
    /// Note that `AclAdmin::Super` grants admin rights for _every_ role. Hence,
    /// if `account_id` has the corresponding permissions
    /// [`AclPermissions::SUPER_ADMIN`], this function returns true for every
    /// `Role`.
    fn is_admin(&self, role: Role, account_id: &AccountId) -> bool {
        let permissions = {
            match self.permissions.get(account_id) {
                Some(permissions) => permissions,
                None => return false,
            }
        };
        permissions.contains(AclPermissions::SUPER_ADMIN)
            || permissions.contains(role.admin().into())
    }

    /// Adds `account_id` the of admins for `role`, given that the
    /// predecessor is an admin for `role`. Returns `Some(bool)` indicating
    /// whether `account_id` has gained new admin permissions.
    ///
    /// If the predecessor is not and admin for `role`, `account_id` is not
    /// added to the set of admins and `None` is returned.
    fn add_admin(&mut self, role: Role, account_id: &AccountId) -> Option<bool> {
        // TODO discuss: two lookups happen here: is_admin() + add_admin_unchecked().
        // What's more important: DRY+readability or micro optimization (avoid methods
        // to bring the number of lookups down to one)? Same at other places which
        // call `is_admin()` before doing a modifications.
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        Some(self.add_admin_unchecked(role, account_id))
    }

    /// Grants admin permissions for `role` to `account_id`, __without__
    /// checking permissions of the predecessor.
    ///
    /// Returns whether `account_id` was newly added to the admins for `role`.
    fn add_admin_unchecked(&mut self, role: Role, account_id: &AccountId) -> bool {
        let flag: AclPermissions = role.admin().into();
        let mut permissions = self.get_or_init_permissions(account_id);

        let is_new_admin = !permissions.contains(flag);
        if is_new_admin {
            permissions.insert(flag);
            self.permissions.insert(account_id, &permissions);
            AclEvent::new_from_env(AclEventId::AdminAdded, role, account_id.clone()).emit();
        }

        is_new_admin
    }

    /// Revoke admin permissions for `role` from `account_id`. If the
    /// predecessor is an admin for `role`, it returns `Some<bool>` indicating
    /// whether `account_id` was an admin.
    ///
    /// If the predecessor is not an admin for `role`, it returns `None`
    /// permissions are not modified.
    fn revoke_admin(&mut self, role: Role, account_id: &AccountId) -> Option<bool> {
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        Some(self.revoke_admin_unchecked(role, account_id))
    }

    /// Revokes admin rights for `role` from the calling account. Returns
    /// whether the caller was an admin for `role`.
    fn renounce_admin(&mut self, role: Role) -> bool {
        self.revoke_admin_unchecked(role, &env::predecessor_account_id())
    }

    /// Revokes admin rights for `role` from `account_id` without checking any
    /// permissions. Returns whether `account_id` was an admin for `role`.
    fn revoke_admin_unchecked(&mut self, role: Role, account_id: &AccountId) -> bool {
        let flag: AclPermissions = role.admin().into();
        let mut permissions = self.get_or_init_permissions(account_id);

        let was_admin = permissions.contains(flag);
        if !was_admin {
            permissions.remove(flag);
            self.permissions.insert(account_id, &permissions);
            AclEvent::new_from_env(AclEventId::AdminRevoked, role, account_id.clone()).emit();
        }

        was_admin
    }

    /// Returns whether `account_id` has been granted `role`.
    fn has_role(&self, role: Role, account_id: &AccountId) -> bool {
        match self.permissions.get(account_id) {
            Some(permissions) => permissions.contains(role.into()),
            None => false,
        }
    }

    /// Grants `role` to `account_id`, given that the predecessor is an admin
    /// for `role`. Returns `Some(bool)` indicating wheter `role` was newly
    /// granted to `account_id`.
    ///
    /// If the predecessor is not an admin for `role`, `account_id` is not
    /// granted the role and `None` is returned.
    fn grant_role(&mut self, role: Role, account_id: &AccountId) -> Option<bool> {
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        Some(self.grant_role_unchecked(role, account_id))
    }

    /// Grants `role` to `account_id` __without__ checking any permissions.
    /// Returns whether `role` was newly granted to `account_id`.
    fn grant_role_unchecked(&mut self, role: Role, account_id: &AccountId) -> bool {
        let flag: AclPermissions = role.into();
        let mut permissions = self.get_or_init_permissions(account_id);

        let is_new_grantee = !permissions.contains(flag);
        if is_new_grantee {
            permissions.insert(flag);
            self.permissions.insert(account_id, &permissions);
            AclEvent::new_from_env(AclEventId::RoleGranted, role, account_id.clone()).emit();
        }

        is_new_grantee
    }

    /// Revoke `role` from `account_id`. If the predecessor is an admin for
    /// `role`, it returns `Some(bool)` indicating whether `account_id` was a
    /// grantee of `role`.
    ///
    /// If the predecessor is not an admin for `role`, it returns `None` and
    /// permissions are not modified.
    fn revoke_role(&mut self, role: Role, account_id: &AccountId) -> Option<bool> {
        if !self.is_admin(role, &env::predecessor_account_id()) {
            return None;
        }
        Some(self.revoke_role_unchecked(role, account_id))
    }

    /// Revokes `role` from `account_id` without checking any permissions.
    /// Returns whether `account_id` was a grantee of `role`.
    fn revoke_role_unchecked(&mut self, role: Role, account_id: &AccountId) -> bool {
        let flag: AclPermissions = role.into();
        let mut permissions = self.get_or_init_permissions(account_id);

        let was_grantee = permissions.contains(flag);
        if was_grantee {
            permissions.remove(flag);
            self.permissions.insert(account_id, &permissions);
            AclEvent::new_from_env(AclEventId::RoleRevoked, role, account_id.clone()).emit();
        }

        was_grantee
    }

    /// Revokes `role` from the calling account. Returns whether the caller was
    /// a grantee of `role`.
    fn renounce_role(&mut self, role: Role) -> bool {
        self.revoke_role_unchecked(role, &env::predecessor_account_id())
    }

    /// Panics if `account_id` does not have at least one of the permissions
    /// specified in `target`.
    fn check_any(&self, target: AclPermissions, account_id: &AccountId) {
        let permissions = self.get_or_init_permissions(account_id);
        // TODO check cost and output of `fmt()` for `AclPermissions`
        require!(
            permissions.intersects(target),
            format!(
                "Account {} has must have at least one role of {:?}",
                account_id, target
            ),
        )
    }

    /// Panics if `account_id` does not have all of the permissions specified in
    /// `target`.
    fn check_all(&self, target: AclPermissions, account_id: &AccountId) {
        let permissions = self.get_or_init_permissions(account_id);
        // TODO check cost and output of `fmt()` for `AclPermissions`
        require!(
            permissions.contains(target),
            format!("Account {} must have all roles in {:?}", account_id, target,)
        )
    }
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
    AdminRevoked,
    RoleGranted,
    RoleRevoked,
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
            Self::AdminRevoked => "acl_admin_revoked",
            Self::RoleGranted => "acl_role_granted",
            Self::RoleRevoked => "acl_role_revoked",
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
