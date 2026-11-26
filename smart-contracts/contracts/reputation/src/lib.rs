#![no_std]

//! # Reputation Contract
//!
//! Manages agent reputation on the Stellar network, including time-locked
//! linear vesting schedules for platform token rewards.
//!
//! ## Vesting Overview
//!
//! To prevent short-term pump-and-dump dynamics, earned rewards are locked in a
//! linear vesting schedule. Agents can claim their proportional share at any
//! point during the vesting window:
//!
//! ```text
//! elapsed   = min(now - start_timestamp, duration_seconds)
//! vested    = total_amount * elapsed / duration_seconds
//! claimable = vested - claimed_amount
//! ```
//!
//! ## Public Functions
//!
//! | Function                   | Description                                        |
//! |----------------------------|----------------------------------------------------|
//! | `initialize`               | One-time admin setup                               |
//! | `create_vesting_schedule`  | Admin: create a vesting schedule for an agent      |
//! | `claim_vested`             | Agent: claim currently vested tokens               |
//! | `get_vesting_state`        | Read-only: schedule + claimable at current time    |

pub mod vesting;
mod errors;

pub use errors::Error;
pub use vesting::{VestingSchedule, VestingState, DataKey};

use soroban_sdk::{contract, contractimpl, Address, Env};

// ─── TTL constants ────────────────────────────────────────────────────────────

const TTL_THRESHOLD: u32 = 100_000;
const TTL_EXTEND_TO: u32 = 535_680;

// ─── Contract ──────────────────────────────────────────────���─────────────────

#[contract]
pub struct ReputationContract;

#[contractimpl]
impl ReputationContract {
    // ── Initialisation ───────────────────────────────────────────────────────

    /// One-time initialisation: set the contract admin.
    ///
    /// # Errors
    ///
    /// * [`Error::AlreadyInitialized`] — called more than once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
        Ok(())
    }

    // ── Vesting ──────────────────────────────────────────────────────────────

    /// **Admin-only.** Create a linear vesting schedule for `agent_id`.
    ///
    /// # Arguments
    ///
    /// * `agent_id`  — the agent that will be able to claim the tokens.
    /// * `amount`    — total tokens to vest (must be > 0).
    /// * `start`     — UNIX timestamp at which vesting begins.
    /// * `duration`  — length of the vesting period in seconds (must be > 0).
    ///
    /// # Errors
    ///
    /// * [`Error::NotInitialized`]      — `initialize` has not been called.
    /// * [`Error::Unauthorized`]        — caller is not the admin.
    /// * [`Error::InvalidAmount`]       — `amount ≤ 0`.
    /// * [`Error::InvalidDuration`]     — `duration == 0`.
    /// * [`Error::VestingAlreadyExists`] — agent already has an active schedule.
    pub fn create_vesting_schedule(
        env: Env,
        agent_id: Address,
        amount: i128,
        start: u64,
        duration: u64,
    ) -> Result<(), Error> {
        Self::require_initialized(&env)?;
        let admin = Self::load_admin(&env)?;
        // The caller must be the admin; `create_vesting_schedule` checks this.
        vesting::create_vesting_schedule(&env, &admin, &admin, agent_id, amount, start, duration)
    }

    /// Claim all currently vested tokens for `agent_id`.
    ///
    /// Returns the number of tokens transferred in this call. Returns `0` when
    /// nothing new has vested since the last claim (idempotent for the same
    /// ledger).
    ///
    /// # Errors
    ///
    /// * [`Error::VestingNotFound`]   — no schedule exists for this agent.
    /// * [`Error::VestingNotStarted`] — `ledger().timestamp() < start_timestamp`.
    pub fn claim_vested(env: Env, agent_id: Address) -> Result<i128, Error> {
        Self::require_initialized(&env)?;
        vesting::claim_vested(&env, agent_id)
    }

    /// Return the vesting schedule and currently claimable amount for `agent_id`.
    ///
    /// Returns `claimable = 0` when vesting has not yet started, so callers can
    /// inspect the schedule freely without an error.
    ///
    /// # Errors
    ///
    /// * [`Error::VestingNotFound`] — no schedule exists for this agent.
    pub fn get_vesting_state(env: Env, agent_id: Address) -> Result<VestingState, Error> {
        Self::require_initialized(&env)?;
        vesting::get_vesting_state(&env, agent_id)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn require_initialized(env: &Env) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            Ok(())
        } else {
            Err(Error::NotInitialized)
        }
    }

    fn load_admin(env: &Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }
}
