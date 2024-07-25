### Issue in Validator Announce Implementation

#### **Overview**

This document outlines a problem encountered in the validator announcement mechanism, specifically within the transition from an older Fuel contract system to the latest Sway implementation. The key issue lies in the mismatch between the expected validator and signer addresses during the announcement process.

The primary goal of the `ValidatorAnnounce` contract is to allow validators to announce their storage locations securely. Each announcement includes the validator's address, the storage location, and a signature. The integrity of these announcements is ensured through cryptographic verification of the signer’s identity against the provided validator address.

#### **Main Problem Description**

During the execution of the `announce` function, the contract attempts to verify that the signer of the announcement matches the validator address provided. The function uses `ec_recover_evm_address` to recover the signer's address from the provided signature and the announcement hash (received from `get_announcement_digest`).

**Current Implementation:**
```rust
let message_hash = get_announcement_digest(MAILBOX_ID, LOCAL_DOMAIN, storage_location.clone());
let signer = ec_recover_evm_address(signature, message_hash).unwrap();

if validator.bits() != signer.bits() {
    log("Validator and signer do not match");
}
```

Despite the implementation seeming similar to old sway contracts, the logs indicate that the `validator.bits()` and `signer.bits()` values do not match. This suggests a discrepancy between the expected and actual recovered addresses. Despite logging various steps, including function outputs and intermediate hashes, the exact cause remains unclear from the logs alone. The logs include detailed byte arrays and hexadecimal values, but these outputs do not directly reveal the underlying issue.
