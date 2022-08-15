# Purpose
Provide a draft of how code should look after `ACL` from [`near-plugins`](https://github.com/aurora-is-near/near-plugins) was expanded. The `ACL` feature for `near-plugins` is currently being developed.

The contract can be built with:

```
make build
```

# `ACL` usage
For smart contract developers, using that feature should work like the following:

```rust
use near_sdk::{env, near_bindgen, AccountId};

/// Roles are represented by enum variants.
enum Role {
    L1,
    L2,
    L3,
}

#[near_bindgen]
#[derive(AccessContralable)]
// Passing `Role` to `AccessControlable` via `access_control`, see
// https://stackoverflow.com/a/56198097
#[access_control(Role)]
pub struct Counter {
    counter: u64,
}

#[near_bindgen]
impl Counter {
    /// Grant initial roles.
    #[init]
    pub fn new() -> Self {
        let mut contract = Self { counter: 0 };

        let caller = env::predecessor_account_id();
        contract.acl.add_admin_unchecked(Role::L1, &caller);
        contract.acl.add_admin_unchecked(Role::L2, &caller);
        contract.acl.add_admin_unchecked(Role::L3, &caller);

        contract
    }

    /// Checking roles within a method.
    pub fn foo1() {
        if self.acl.has_role(Role::L1, &env::predecessor_account_id()) {
            // ...
        }
    }

    /// Restrict call to _one_ role.
    /// 
    /// Having a separate attribute to check for a _single_ role could make it
    /// easier to optimize that case. If not, keep only `acl_any`.
    #[acl_only(Role::L1)]
    pub fn foo2() {}

    /// Make it possible to restrict call to _some_  roles?
    #[acl_any(Role::L1, Role::L2)]
    pub fn foo3() {}

    /// Make it possible to restrict call to _all_ roles?
    #[acl_all(Role)]
    pub fn foo4() {}
}
```
