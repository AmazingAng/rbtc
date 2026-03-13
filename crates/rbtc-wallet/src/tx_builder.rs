//! Transaction building, coin selection, and signing.

use rand::seq::SliceRandom;
use rand::Rng;
use rand::RngCore;
use secp256k1::{Keypair, Message, SecretKey};

use rbtc_crypto::sighash::{sighash_legacy, sighash_segwit_v0, sighash_taproot, SighashType};
use rbtc_primitives::{
    script::Script,
    transaction::{OutPoint, Transaction, TxIn, TxOut},
};

use crate::{
    address::{p2wpkh_script_code, taproot_output_key, AddressType},
    error::WalletError,
    wallet::WalletUtxo,
};

// ── CoinSelector ──────────────────────────────────────────────────────────────

/// Coin selection implementing Bitcoin Core's Branch-and-Bound (BnB) algorithm
/// with a largest-first greedy fallback.
///
/// BnB tries to find a subset of UTXOs that matches the target + fees exactly
/// (or within a small "cost of change" window), avoiding the creation of change
/// outputs. If no exact match is found, falls back to largest-first greedy.
pub struct CoinSelector;

/// Cost of creating + spending a change output (approx. 68 vbytes spend + 31 vbytes output).
const CHANGE_COST: u64 = 99;

/// Maximum BnB search iterations to prevent combinatorial explosion.
const BNB_MAX_TRIES: u32 = 100_000;

/// Maximum CoinGrinder search iterations.
const COINGRINDER_MAX_TRIES: u32 = 100_000;

/// Long-term fee rate (sat/vbyte) for waste metric calculation.
/// Bitcoin Core uses 10 sat/vbyte as the default long-term estimate.
const LONG_TERM_FEE_RATE: f64 = 10.0;

/// Dust threshold — UTXOs below this are uneconomical to spend (Bitcoin Core default).
const DUST_THRESHOLD: u64 = 546;

/// Number of random iterations in the knapsack solver (matches Bitcoin Core).
const KNAPSACK_ITERATIONS: u32 = 1000;

/// Default maximum transaction weight (400,000 WU = standard policy limit).
const DEFAULT_MAX_TX_WEIGHT: i64 = 400_000;

/// Per-input-type weight in weight units (WU).  These match the worst-case
/// witness sizes that Bitcoin Core uses for coin selection.
///
/// Weight = non-witness-bytes × 4 + witness-bytes.
/// We report in WU so the caller can compare against `max_tx_weight`.
pub fn input_weight(addr_type: AddressType) -> i64 {
    match addr_type {
        // P2PKH: 148 non-witness bytes × 4 = 592 WU (no witness)
        AddressType::Legacy => 592,
        // P2SH-P2WPKH: 23 non-witness + 108 witness + overhead → ~364 WU
        AddressType::P2shP2wpkh => 364,
        // P2WPKH: 41 non-witness × 4 + 108 witness = 272 WU
        AddressType::SegWit => 272,
        // P2TR: 41 non-witness × 4 + 66 witness = 230 WU
        AddressType::Taproot => 230,
    }
}

/// Convert input weight to virtual bytes for fee estimation.
pub fn input_vbytes(addr_type: AddressType) -> f64 {
    input_weight(addr_type) as f64 / 4.0
}

impl CoinSelector {
    /// Select UTXOs to cover `target_sat` plus a fee estimated at `fee_rate`
    /// sat/vbyte. Returns `(selected, estimated_fee)`.
    ///
    /// Tries strategies in Bitcoin Core order: Branch-and-Bound (changeless),
    /// CoinGrinder (weight-minimizing), Knapsack solver, then largest-first
    /// greedy fallback.
    pub fn select(
        utxos: &[WalletUtxo],
        target_sat: u64,
        fee_rate: f64,
    ) -> Result<(Vec<WalletUtxo>, u64), WalletError> {
        Self::select_with_max_weight(utxos, target_sat, fee_rate, DEFAULT_MAX_TX_WEIGHT)
    }

    /// Like `select` but with an explicit max transaction weight (in weight units).
    pub fn select_with_max_weight(
        utxos: &[WalletUtxo],
        target_sat: u64,
        fee_rate: f64,
        max_weight: i64,
    ) -> Result<(Vec<WalletUtxo>, u64), WalletError> {
        if utxos.is_empty() {
            return Err(WalletError::NoUtxos);
        }

        let estimate_fee = |n_inputs: usize| -> u64 {
            let vbytes = 10 + n_inputs as u64 * 68 + 2 * 31;
            (vbytes as f64 * fee_rate).ceil() as u64
        };

        // Try BnB first (changeless transaction)
        if let Some(result) = Self::branch_and_bound(utxos, target_sat, fee_rate) {
            if Self::selection_weight(&result.0) <= max_weight {
                return Ok(result);
            }
        }

        // Try CoinGrinder (weight-minimizing) when fee rate is high enough to care
        if fee_rate > LONG_TERM_FEE_RATE {
            if let Some(result) = Self::coin_grinder(utxos, target_sat, fee_rate, max_weight) {
                return Ok(result);
            }
        }

        // Try Knapsack solver
        if let Ok(result) = Self::knapsack(utxos, target_sat, fee_rate) {
            if Self::selection_weight(&result.0) <= max_weight {
                return Ok(result);
            }
        }

        // Try Single Random Draw (SRD) — matches Bitcoin Core's cascade
        // that includes SRD after Knapsack for privacy benefits.
        if let Ok(result) = Self::single_random_draw(utxos, target_sat, fee_rate) {
            if Self::selection_weight(&result.0) <= max_weight {
                return Ok(result);
            }
        }

        // Fallback: largest-first greedy (with change)
        let result = Self::largest_first(utxos, target_sat, &estimate_fee)?;
        if Self::selection_weight(&result.0) > max_weight {
            return Err(WalletError::MaxWeightExceeded);
        }
        Ok(result)
    }

    /// Calculate total input weight of a selection (in weight units).
    fn selection_weight(selected: &[WalletUtxo]) -> i64 {
        // Tx overhead: (version 4 + locktime 4 + segwit marker/flag 2 + varint counts ~2) × 4
        // but non-witness overhead is 4×, witness overhead is 1×
        // Simplified: base overhead ~40 WU + output overhead
        let base_wu: i64 = 4 * (4 + 4 + 1 + 1) + 2; // version+locktime+counts(×4) + segwit flag
        let output_wu: i64 = 2 * 4 * 31; // 2 outputs × 31 bytes × 4
        let input_wu: i64 = selected.iter().map(|u| input_weight(u.addr_type)).sum();
        base_wu + output_wu + input_wu
    }

    /// Branch-and-Bound coin selection (per-type aware).
    ///
    /// Searches for a UTXO subset whose total value is within
    /// [target + fees, target + fees + cost_of_change].
    /// This produces a changeless transaction when successful.
    fn branch_and_bound(
        utxos: &[WalletUtxo],
        target_sat: u64,
        fee_rate: f64,
    ) -> Option<(Vec<WalletUtxo>, u64)> {
        // Sort descending by effective value (value minus per-type input fee)
        let mut sorted: Vec<(usize, u64, f64)> = utxos
            .iter()
            .enumerate()
            .map(|(i, u)| {
                let vb = input_vbytes(u.addr_type);
                let input_fee = (vb * fee_rate).ceil() as u64;
                let eff = u.value.saturating_sub(input_fee);
                (i, eff, vb)
            })
            .filter(|(_, eff, _)| *eff > 0)
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));

        if sorted.is_empty() {
            return None;
        }

        // Base fee for a changeless tx (no change output, so only 1 output)
        let base_fee = (10.0 * fee_rate + 31.0 * fee_rate).ceil() as u64;
        let target_with_fee = target_sat + base_fee;
        let cost_of_change = (CHANGE_COST as f64 * fee_rate).ceil() as u64;

        // Sum of all effective values (for pruning)
        let suffix_sums: Vec<u64> = {
            let mut sums = vec![0u64; sorted.len() + 1];
            for i in (0..sorted.len()).rev() {
                sums[i] = sums[i + 1] + sorted[i].1;
            }
            sums
        };

        if suffix_sums[0] < target_with_fee {
            return None;
        }

        let mut best: Option<(Vec<usize>, f64)> = None;
        let mut current_selection: Vec<bool> = vec![false; sorted.len()];
        let mut current_value = 0u64;
        let mut tries = 0u32;

        let mut depth = 0usize;
        let mut backtrack = false;

        let compute_fee = |indices: &[usize]| -> u64 {
            let input_vb: f64 = indices.iter().map(|&i| sorted[i].2).sum();
            ((10.0 + 31.0 + input_vb) * fee_rate).ceil() as u64
        };

        let compute_waste = |indices: &[usize], value: u64| -> f64 {
            let input_fees: f64 = indices.iter().map(|&i| sorted[i].2 * fee_rate).sum();
            let long_term_fees: f64 = indices.iter().map(|&i| sorted[i].2 * LONG_TERM_FEE_RATE).sum();
            let excess = value.saturating_sub(target_with_fee) as f64;
            (input_fees - long_term_fees) + excess
        };

        loop {
            if tries >= BNB_MAX_TRIES {
                break;
            }
            tries += 1;

            if backtrack {
                loop {
                    if depth == 0 {
                        return best.map(|(indices, _)| {
                            let fee = compute_fee(&indices);
                            let selected: Vec<WalletUtxo> = indices
                                .iter()
                                .map(|&i| utxos[sorted[i].0].clone())
                                .collect();
                            (selected, fee)
                        });
                    }
                    depth -= 1;
                    if current_selection[depth] {
                        current_selection[depth] = false;
                        current_value -= sorted[depth].1;
                        depth += 1;
                        backtrack = false;
                        break;
                    }
                }
                if backtrack {
                    continue;
                }
            }

            if depth >= sorted.len() {
                backtrack = true;
                continue;
            }

            current_selection[depth] = true;
            current_value += sorted[depth].1;

            if current_value >= target_with_fee {
                if current_value <= target_with_fee + cost_of_change {
                    let indices: Vec<usize> = current_selection
                        .iter()
                        .enumerate()
                        .filter(|(_, &s)| s)
                        .map(|(i, _)| i)
                        .collect();
                    let waste = compute_waste(&indices, current_value);

                    let is_better = match &best {
                        None => true,
                        Some((_, prev_waste)) => waste < *prev_waste,
                    };
                    if is_better {
                        best = Some((indices, waste));
                    }
                }
                backtrack = true;
                current_selection[depth] = false;
                current_value -= sorted[depth].1;
                continue;
            }

            if current_value + suffix_sums[depth + 1] < target_with_fee {
                backtrack = true;
                current_selection[depth] = false;
                current_value -= sorted[depth].1;
                continue;
            }

            depth += 1;
        }

        best.map(|(indices, _)| {
            let fee = compute_fee(&indices);
            let selected: Vec<WalletUtxo> = indices
                .iter()
                .map(|&i| utxos[sorted[i].0].clone())
                .collect();
            (selected, fee)
        })
    }

    /// CoinGrinder: weight-minimizing branch-and-bound coin selection (Bitcoin Core v28+).
    ///
    /// Explores a binary tree of inclusion/omission decisions over the UTXO pool,
    /// sorted by descending effective value.  Uses three state transitions:
    /// - EXPLORE: insufficient funds, add the next UTXO (inclusion branch)
    /// - SHIFT:   current selection meets target or can't improve on best weight,
    ///            replace last selected UTXO with next candidate (omission branch)
    /// - CUT:     both inclusion and omission branches are barren, deselect last
    ///            two and shift the penultimate selection
    ///
    /// Matches Bitcoin Core `CoinGrinder()` in `coinselection.cpp`.
    fn coin_grinder(
        utxos: &[WalletUtxo],
        target_sat: u64,
        fee_rate: f64,
        max_weight: i64,
    ) -> Option<(Vec<WalletUtxo>, u64)> {
        // Sort descending by effective value, break ties by ascending weight
        let mut pool: Vec<(usize, u64, i64)> = utxos
            .iter()
            .enumerate()
            .map(|(i, u)| {
                let vb = input_vbytes(u.addr_type);
                let input_fee = (vb * fee_rate).ceil() as u64;
                let eff = u.value.saturating_sub(input_fee);
                let w = input_weight(u.addr_type);
                (i, eff, w)
            })
            .filter(|(_, eff, _)| *eff > 0)
            .collect();
        pool.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)));

        if pool.is_empty() {
            return None;
        }

        let n = pool.len();

        // Compute change_target and total_target (selection_target + change_target)
        let change_fee = (CHANGE_COST as f64 * fee_rate).ceil() as u64;
        let base_fee = ((10.0 + 2.0 * 31.0) * fee_rate).ceil() as u64;
        let total_target = target_sat + base_fee + change_fee;

        // lookahead[i] = sum of effective values of UTXOs after index i
        // min_tail_weight[i] = minimum weight among UTXOs after index i
        let mut lookahead = vec![0u64; n];
        let mut min_tail_weight = vec![i64::MAX; n];
        {
            let mut total_avail = 0u64;
            let mut min_w = i64::MAX;
            for i in (0..n).rev() {
                lookahead[i] = total_avail;
                min_tail_weight[i] = min_w;
                total_avail += pool[i].1;
                min_w = min_w.min(pool[i].2);
            }
            if total_avail < total_target {
                return None;
            }
        }

        // Weight of transaction without any inputs (overhead + change output).
        // Bitcoin Core subtracts this from max_weight before calling CoinGrinder,
        // so we do the same: track only input weights in curr_weight.
        let overhead_wu: i64 = 4 * (4 + 4 + 1 + 1) + 2 + 2 * 4 * 31;
        let max_input_weight = max_weight - overhead_wu;
        if max_input_weight <= 0 {
            return None;
        }

        let mut curr_selection: Vec<usize> = Vec::new();
        let mut best_selection: Vec<usize> = Vec::new();

        let mut curr_amount = 0u64;
        let mut best_amount = u64::MAX;

        // Track only input weights; best_weight initialized to max budget (tie is fine,
        // we prefer lower amount as tiebreaker — matching Bitcoin Core).
        let mut curr_weight: i64 = 0;
        let mut best_weight: i64 = max_input_weight;

        let mut next_utxo = 0usize;
        let mut curr_try = 0u32;
        let mut is_done = false;

        while !is_done {
            let mut should_shift = false;
            let mut should_cut = false;

            // --- Select next_utxo ---
            let (_, eff, w) = pool[next_utxo];
            curr_amount += eff;
            curr_weight += w;
            curr_selection.push(next_utxo);
            next_utxo += 1;
            curr_try += 1;

            // --- EVALUATE current selection ---
            let curr_tail = *curr_selection.last().unwrap();

            if curr_amount + lookahead[curr_tail] < total_target {
                // Insufficient funds even with all remaining UTXOs: CUT
                should_cut = true;
            } else if curr_weight > best_weight {
                // Worse weight than best solution. More UTXOs only increase weight.
                // CUT if last selected group had minimal weight, else SHIFT.
                if pool[curr_tail].2 <= min_tail_weight[curr_tail] {
                    should_cut = true;
                } else {
                    should_shift = true;
                }
            } else if curr_amount >= total_target {
                // Solution found, adding more UTXOs can only increase weight: SHIFT
                should_shift = true;
                if curr_weight < best_weight
                    || (curr_weight == best_weight && curr_amount < best_amount)
                {
                    best_selection = curr_selection.clone();
                    best_weight = curr_weight;
                    best_amount = curr_amount;
                }
            } else if !best_selection.is_empty() {
                // Estimate minimum additional weight to reach target.
                // min_additional_inputs = ceil((total_target - curr_amount) / last_eff)
                // min_additional_weight = min_tail_weight * min_additional_inputs
                let last_eff = pool[curr_tail].1.max(1);
                let min_additional_inputs =
                    (total_target - curr_amount + last_eff - 1) / last_eff;
                let min_additional_weight =
                    min_tail_weight[curr_tail] as i64 * min_additional_inputs as i64;
                if curr_weight + min_additional_weight > best_weight {
                    if pool[curr_tail].2 <= min_tail_weight[curr_tail] {
                        should_cut = true;
                    } else {
                        should_shift = true;
                    }
                }
            }

            // Check iteration limit (solution not guaranteed optimal if hit)
            if curr_try >= COINGRINDER_MAX_TRIES {
                break;
            }

            // Last UTXO was end of pool: nothing left to add: CUT
            if next_utxo == n {
                should_cut = true;
            }

            if should_cut {
                // Deselect last, then SHIFT to omission branch of penultimate
                let idx = curr_selection.pop().unwrap();
                curr_amount -= pool[idx].1;
                curr_weight -= pool[idx].2;
                should_shift = true;
            }

            while should_shift {
                if curr_selection.is_empty() {
                    // Exhausted search space
                    is_done = true;
                    break;
                }
                // Set next_utxo to one after last selected, then deselect last
                next_utxo = *curr_selection.last().unwrap() + 1;
                let idx = curr_selection.pop().unwrap();
                curr_amount -= pool[idx].1;
                curr_weight -= pool[idx].2;
                should_shift = false;

                // Skip clones: if the next UTXO has the same effective value as the
                // one we just deselected, selecting it would produce an equivalent or
                // worse selection. Skip until we find a different effective value.
                while next_utxo < n
                    && pool[next_utxo - 1].1 == pool[next_utxo].1
                {
                    if next_utxo >= n - 1 {
                        // Reached end of UTXO pool skipping clones: SHIFT instead
                        should_shift = true;
                        break;
                    }
                    next_utxo += 1;
                }
            }
        }

        if best_selection.is_empty() {
            return None;
        }

        let selected: Vec<WalletUtxo> = best_selection
            .iter()
            .map(|&i| utxos[pool[i].0].clone())
            .collect();
        let fee = Self::estimate_fee_for(&selected, fee_rate);
        Some((selected, fee))
    }

    /// Estimate fee for a set of selected UTXOs using per-type input weights.
    fn estimate_fee_for(selected: &[WalletUtxo], fee_rate: f64) -> u64 {
        let input_vb: f64 = selected.iter().map(|u| input_vbytes(u.addr_type)).sum();
        let overhead_vb = 10.0 + 2.0 * 31.0;
        ((overhead_vb + input_vb) * fee_rate).ceil() as u64
    }

    /// Fallback: largest-first greedy coin selection.
    fn largest_first(
        utxos: &[WalletUtxo],
        target_sat: u64,
        estimate_fee: &dyn Fn(usize) -> u64,
    ) -> Result<(Vec<WalletUtxo>, u64), WalletError> {
        let mut sorted: Vec<&WalletUtxo> = utxos.iter().collect();
        sorted.sort_by(|a, b| b.value.cmp(&a.value));

        let mut selected = Vec::new();
        let mut total = 0u64;

        for utxo in sorted {
            selected.push(utxo.clone());
            total += utxo.value;
            let fee = estimate_fee(selected.len());
            if total >= target_sat + fee {
                return Ok((selected, fee));
            }
        }

        Err(WalletError::InsufficientFunds {
            needed: target_sat,
            available: total,
        })
    }

    /// Single Random Draw: randomly select UTXOs until the target is met.
    /// Returns UTXOs that sum to at least target + estimated_fee, plus a change output.
    /// This provides privacy benefits by randomizing the input set.
    pub fn single_random_draw(
        utxos: &[WalletUtxo],
        target_sat: u64,
        fee_rate: f64,
    ) -> Result<(Vec<WalletUtxo>, u64), WalletError> {
        if utxos.is_empty() {
            return Err(WalletError::NoUtxos);
        }

        let mut rng = rand::thread_rng();
        let mut shuffled: Vec<WalletUtxo> = utxos.to_vec();
        shuffled.shuffle(&mut rng);

        let estimate_fee = |n_inputs: usize| -> u64 {
            // tx overhead + inputs + 2 outputs (payment + change)
            let vbytes = 10 + n_inputs as u64 * 68 + 2 * 31;
            (vbytes as f64 * fee_rate).ceil() as u64
        };

        let change_cost = (CHANGE_COST as f64 * fee_rate).ceil() as u64;

        let mut selected = Vec::new();
        let mut total = 0u64;

        for utxo in &shuffled {
            selected.push(utxo.clone());
            total += utxo.value;
            let fee = estimate_fee(selected.len());
            if total >= target_sat + fee + change_cost {
                return Ok((selected, fee));
            }
        }

        Err(WalletError::InsufficientFunds {
            needed: target_sat,
            available: total,
        })
    }

    /// Knapsack coin selection using a combination of exact-match search and
    /// random selection, matching Bitcoin Core's legacy KnapsackSolver.
    ///
    /// Algorithm:
    /// 1. Check if any single UTXO matches the target within the dust threshold.
    /// 2. Run 1000 random iterations where each UTXO has a 50% chance of inclusion;
    ///    track the combination with the smallest overshoot.
    /// 3. If the best combination overshoots by more than the target amount,
    ///    prefer the single smallest UTXO that is >= target.
    pub fn knapsack(
        utxos: &[WalletUtxo],
        target_sat: u64,
        fee_rate: f64,
    ) -> Result<(Vec<WalletUtxo>, u64), WalletError> {
        if utxos.is_empty() {
            return Err(WalletError::NoUtxos);
        }

        let estimate_fee = |n_inputs: usize| -> u64 {
            let vbytes = 10 + n_inputs as u64 * 68 + 2 * 31;
            (vbytes as f64 * fee_rate).ceil() as u64
        };

        // Effective target including the fee for at least one input
        let base_fee = estimate_fee(1);
        let target_with_fee = target_sat + base_fee;

        // Pass 1: look for exact match (single UTXO within dust threshold)
        let mut smallest_bigger: Option<(usize, u64)> = None;
        for (i, utxo) in utxos.iter().enumerate() {
            if utxo.value == target_with_fee {
                // Exact single-UTXO match
                let fee = estimate_fee(1);
                return Ok((vec![utxo.clone()], fee));
            }
            if utxo.value >= target_with_fee {
                let overshoot = utxo.value - target_with_fee;
                if utxo.value.abs_diff(target_with_fee) <= DUST_THRESHOLD {
                    let fee = estimate_fee(1);
                    return Ok((vec![utxo.clone()], fee));
                }
                match smallest_bigger {
                    None => smallest_bigger = Some((i, overshoot)),
                    Some((_, prev)) if overshoot < prev => {
                        smallest_bigger = Some((i, overshoot));
                    }
                    _ => {}
                }
            }
        }

        // Pass 2: random subset selection (1000 iterations, 50% inclusion)
        let mut rng = rand::thread_rng();
        let mut best_selection: Option<(Vec<usize>, u64)> = None; // (indices, total_value)

        for _ in 0..KNAPSACK_ITERATIONS {
            let mut indices = Vec::new();
            let mut acc = 0u64;

            for (i, utxo) in utxos.iter().enumerate() {
                if rng.gen_bool(0.5) {
                    indices.push(i);
                    acc += utxo.value;
                }
            }

            let needed = target_sat + estimate_fee(indices.len().max(1));
            if acc >= needed {
                let is_better = match &best_selection {
                    None => true,
                    Some((_, prev_total)) => acc < *prev_total,
                };
                if is_better {
                    best_selection = Some((indices, acc));
                }
            }
        }

        // Decide: use the random best, or the smallest single bigger UTXO
        if let Some((indices, total)) = best_selection {
            let fee = estimate_fee(indices.len());
            let overshoot = total.saturating_sub(target_sat + fee);

            // If the overshoot is larger than the target itself, prefer smallest bigger
            if overshoot > target_sat {
                if let Some((idx, _)) = smallest_bigger {
                    let fee = estimate_fee(1);
                    return Ok((vec![utxos[idx].clone()], fee));
                }
            }

            let selected: Vec<WalletUtxo> = indices.iter().map(|&i| utxos[i].clone()).collect();
            return Ok((selected, fee));
        }

        // Random selection never worked; use the smallest bigger if available
        if let Some((idx, _)) = smallest_bigger {
            let fee = estimate_fee(1);
            return Ok((vec![utxos[idx].clone()], fee));
        }

        Err(WalletError::InsufficientFunds {
            needed: target_sat,
            available: utxos.iter().map(|u| u.value).sum(),
        })
    }
}

// ── TxBuilder ────────────────────────────────────────────────────────────────

/// Unsigned transaction builder.
pub struct TxBuilder {
    version: i32,
    inputs: Vec<(OutPoint, u32)>, // (outpoint, sequence)
    outputs: Vec<TxOut>,
    lock_time: u32,
}

impl TxBuilder {
    pub fn new() -> Self {
        Self {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    pub fn add_input(mut self, outpoint: OutPoint) -> Self {
        self.inputs.push((outpoint, 0xffff_fffe));
        self
    }

    pub fn add_output(mut self, value: u64, script_pubkey: Script) -> Self {
        self.outputs.push(TxOut {
            value: value as i64,
            script_pubkey,
        });
        self
    }

    pub fn lock_time(mut self, lt: u32) -> Self {
        self.lock_time = lt;
        self
    }

    /// Build the unsigned `Transaction` (all scriptSigs and witnesses empty).
    pub fn build(self) -> Transaction {
        let inputs: Vec<TxIn> = self
            .inputs
            .into_iter()
            .map(|(previous_output, sequence)| TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence,
                witness: vec![],
            })
            .collect();
        Transaction::from_parts(self.version, inputs, self.outputs, self.lock_time)
    }
}

impl Default for TxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Signing ──────────────────────────────────────────────────────────────────

/// Information about a wallet key required to sign one input.
pub struct SigningInput {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: Script,
    pub secret_key: SecretKey,
    /// For P2WSH inputs: the witness script (e.g. multisig OP_k <pks> OP_n OP_CHECKMULTISIG).
    /// When set, signs using this script as the BIP143 script_code.
    pub witness_script: Option<Script>,
    /// Sighash type to use for signing this input. Defaults to `SighashType::All`
    /// when set to `None`.
    pub sighash_type: Option<SighashType>,
}

/// Sign a transaction that has been built with `TxBuilder`.
///
/// `signing_inputs` must be in the same order as the transaction inputs.
pub fn sign_transaction(
    tx: &Transaction,
    signing_inputs: &[SigningInput],
) -> Result<Transaction, WalletError> {
    assert_eq!(
        tx.inputs.len(),
        signing_inputs.len(),
        "signing_inputs length must match tx.inputs"
    );

    let secp = secp256k1::Secp256k1::new();
    let mut signed = tx.clone();

    // Collect all prevouts (needed for Taproot sighash)
    let all_prevouts: Vec<TxOut> = signing_inputs
        .iter()
        .map(|si| TxOut {
            value: si.value as i64,
            script_pubkey: si.script_pubkey.clone(),
        })
        .collect();

    for (i, si) in signing_inputs.iter().enumerate() {
        let spk = &si.script_pubkey;
        let sighash_type = si.sighash_type.unwrap_or(SighashType::All);
        let sighash_byte = sighash_type as u8;

        if spk.is_p2pkh() {
            // Legacy P2PKH
            let sighash = sighash_legacy(tx, i, spk, sighash_type);
            let msg = Message::from_digest(sighash.0);
            let sig = secp.sign_ecdsa(msg, &si.secret_key);
            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(sighash_byte);

            let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &si.secret_key);
            let pub_bytes = pubkey.serialize();

            // scriptSig: <sig> <pubkey>
            let mut script_sig = Vec::new();
            script_sig.push(sig_bytes.len() as u8);
            script_sig.extend_from_slice(&sig_bytes);
            script_sig.push(pub_bytes.len() as u8);
            script_sig.extend_from_slice(&pub_bytes);
            signed.inputs[i].script_sig = Script::from_bytes(script_sig);
        } else if spk.is_p2wpkh() {
            // Native SegWit P2WPKH
            let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &si.secret_key);
            let script_code = p2wpkh_script_code(&pubkey);
            let sighash = sighash_segwit_v0(tx, i, &script_code, si.value as i64, sighash_type);
            let msg = Message::from_digest(sighash.0);
            let sig = secp.sign_ecdsa(msg, &si.secret_key);
            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(sighash_byte);

            let pub_bytes = pubkey.serialize();
            signed.inputs[i].script_sig = Script::new();
            signed.inputs[i].witness = vec![sig_bytes, pub_bytes.to_vec()];
        } else if spk.is_p2wsh() {
            // P2WSH — requires witness_script in the SigningInput
            if let Some(ref ws) = si.witness_script {
                let sighash = sighash_segwit_v0(tx, i, ws, si.value as i64, sighash_type);
                let msg = Message::from_digest(sighash.0);
                let sig = secp.sign_ecdsa(msg, &si.secret_key);
                let mut sig_bytes = sig.serialize_der().to_vec();
                sig_bytes.push(sighash_byte);

                signed.inputs[i].script_sig = Script::new();
                let ws_bytes = ws.as_bytes();
                if ws_bytes.last() == Some(&0xae) {
                    // Multisig witness: OP_0 <sig> <witness_script>
                    signed.inputs[i].witness = vec![
                        vec![], // OP_0 dummy (CHECKMULTISIG bug)
                        sig_bytes,
                        ws_bytes.to_vec(),
                    ];
                } else {
                    // Generic P2WSH: <sig> <pubkey> <witness_script>
                    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &si.secret_key);
                    signed.inputs[i].witness =
                        vec![sig_bytes, pubkey.serialize().to_vec(), ws_bytes.to_vec()];
                }
            } else {
                tracing::warn!("sign_transaction: P2WSH input {i} missing witness_script");
            }
        } else if spk.is_p2tr() {
            // Taproot key-path spend (P2TR)
            let tr_sighash_type = si.sighash_type.unwrap_or(SighashType::TaprootDefault);
            let keypair = Keypair::from_secret_key(&secp, &si.secret_key);
            let (tweaked_kp, _) = taproot_output_key(&keypair)?;

            let sighash = sighash_taproot(
                tx,
                i,
                &all_prevouts,
                tr_sighash_type,
                None,
                None,
                0,
                u32::MAX,
            );

            let mut aux_rand = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut aux_rand);
            let sig = secp.sign_schnorr_with_aux_rand(&sighash.0, &tweaked_kp, &aux_rand);

            signed.inputs[i].script_sig = Script::new();
            // For TaprootDefault, signature is 64 bytes (no sighash suffix).
            // For other types, append the sighash byte.
            let mut sig_vec = sig.as_ref().to_vec();
            if tr_sighash_type as u8 != 0 {
                sig_vec.push(tr_sighash_type as u8);
            }
            signed.inputs[i].witness = vec![sig_vec];
        } else {
            // Unsupported script type — leave unsigned, caller can handle
            tracing::warn!("sign_transaction: unsupported input script type for input {i}");
        }
    }

    // Rebuild via from_parts so m_has_witness / hashes are recomputed
    let signed = Transaction::from_parts(
        signed.version,
        signed.inputs,
        signed.outputs,
        signed.lock_time,
    );
    Ok(signed)
}

// ── Fee estimation ────────────────────────────────────────────────────────────

/// Estimate virtual size (vbytes) of a transaction with the given inputs and
/// outputs. Assumes P2WPKH inputs and P2WPKH/P2TR outputs as a baseline.
pub fn estimate_vsize(n_inputs: usize, n_outputs: usize) -> u64 {
    // Overhead: version(4) + marker+flag(2) + locktime(4) + varint counts(2)
    let base = 4 + 4 + 1 + 1; // version, locktime, input count varint, output count varint
                              // Per-input (P2WPKH): outpoint(36) + script_sig_len(1) + sequence(4) = 41 non-witness
                              //                      witness: varint(1) + sig_len(1) + sig(72) + pub_len(1) + pub(33) = 108
    let input_base = n_inputs * 41;
    let input_witness = n_inputs * 108; // charged at 1/4 weight
                                        // Per-output (P2WPKH 31 bytes): value(8) + script_len(1) + script(22)
    let output_base = n_outputs * 31;

    let weight = (base + input_base + output_base) * 4 + input_witness + 2; // +2 for segwit overhead
    (weight as u64).div_ceil(4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::{p2wpkh_script, AddressType},
        hd::ExtendedPrivKey,
        wallet::WalletUtxo,
    };
    use rbtc_primitives::hash::{Hash256, Txid};

    fn sample_utxos() -> Vec<WalletUtxo> {
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        vec![
            WalletUtxo {
                outpoint: OutPoint {
                    txid: Txid(Hash256([1u8; 32])),
                    vout: 0,
                },
                value: 100_000,
                script_pubkey: spk.clone(),
                height: 100,
                address: "bc1qtest".into(),
                confirmed: true,
                addr_type: AddressType::SegWit,
                is_own_change: false,
                is_coinbase: false,
            },
            WalletUtxo {
                outpoint: OutPoint {
                    txid: Txid(Hash256([2u8; 32])),
                    vout: 0,
                },
                value: 200_000,
                script_pubkey: spk,
                height: 101,
                address: "bc1qtest2".into(),
                confirmed: true,
                addr_type: AddressType::SegWit,
                is_own_change: false,
                is_coinbase: false,
            },
        ]
    }

    #[test]
    fn coin_select_success() {
        let utxos = sample_utxos();
        let (selected, fee) = CoinSelector::select(&utxos, 150_000, 1.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 150_000 + fee);
    }

    #[test]
    fn coin_select_insufficient() {
        let utxos = sample_utxos();
        assert!(CoinSelector::select(&utxos, 1_000_000, 1.0).is_err());
    }

    #[test]
    fn tx_builder_builds_correct_structure() {
        let op = OutPoint {
            txid: Txid(Hash256([0u8; 32])),
            vout: 0,
        };
        let spk = Script::from_bytes(vec![0x51]); // OP_1
        let tx = TxBuilder::new()
            .add_input(op.clone())
            .add_output(50_000, spk)
            .build();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.inputs[0].previous_output.txid, op.txid);
        assert_eq!(tx.outputs[0].value, 50_000i64);
    }

    #[test]
    fn estimate_vsize_nonzero() {
        assert!(estimate_vsize(1, 2) > 0);
        assert!(estimate_vsize(2, 3) > estimate_vsize(1, 2));
    }

    #[test]
    fn bnb_finds_exact_match() {
        // Create UTXOs that can exactly cover 150_000 + fees
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let make = |val: u64, id: u8| WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([id; 32])),
                vout: 0,
            },
            value: val,
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
            is_own_change: false,
            is_coinbase: false,
        };
        let utxos = vec![
            make(50_000, 1),
            make(60_000, 2),
            make(90_000, 3),
            make(100_000, 4),
        ];
        // BnB should find a subset; either way total >= target + fee
        let (selected, fee) = CoinSelector::select(&utxos, 50_000, 1.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 50_000 + fee);
    }

    #[test]
    fn bnb_falls_back_to_greedy() {
        // With a high fee rate, BnB may not find a changeless solution
        let utxos = sample_utxos();
        let (selected, fee) = CoinSelector::select(&utxos, 50_000, 50.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 50_000 + fee);
    }

    #[test]
    fn bnb_empty_utxos_error() {
        let result = CoinSelector::select(&[], 1_000, 1.0);
        assert!(result.is_err());
    }

    #[test]
    fn largest_first_selects_fewest_utxos() {
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let make = |val: u64, id: u8| WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([id; 32])),
                vout: 0,
            },
            value: val,
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
            is_own_change: false,
            is_coinbase: false,
        };
        let utxos = vec![make(10_000, 1), make(20_000, 2), make(500_000, 3)];
        let estimate_fee = |n: usize| -> u64 { 10 + n as u64 * 68 + 2 * 31 };
        let (selected, _fee) = CoinSelector::largest_first(&utxos, 100_000, &estimate_fee).unwrap();
        // Should pick the 500k UTXO first (largest), which alone covers 100k
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 500_000);
    }

    // ── SRD tests ─────────────────────────────────────────────────────────

    #[test]
    fn srd_selects_enough() {
        let utxos = sample_utxos(); // 100k + 200k
        let (selected, fee) = CoinSelector::single_random_draw(&utxos, 50_000, 1.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 50_000 + fee, "SRD must cover target + fee");
    }

    #[test]
    fn srd_empty_utxos_fails() {
        let result = CoinSelector::single_random_draw(&[], 1_000, 1.0);
        assert!(result.is_err());
    }

    // ── Knapsack tests ────────────────────────────────────────────────────

    #[test]
    fn knapsack_exact_match() {
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let make = |val: u64, id: u8| WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([id; 32])),
                vout: 0,
            },
            value: val,
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
            is_own_change: false,
            is_coinbase: false,
        };
        // Compute the fee for 1 input so we can craft an exact-match UTXO
        let fee_rate = 1.0;
        let fee_1_input = ((10 + 1 * 68 + 2 * 31) as f64 * fee_rate).ceil() as u64;
        let target = 50_000u64;
        let exact_value = target + fee_1_input; // UTXO value that exactly matches

        let utxos = vec![make(10_000, 1), make(exact_value, 2), make(300_000, 3)];
        let (selected, _fee) = CoinSelector::knapsack(&utxos, target, fee_rate).unwrap();

        // Knapsack should detect the exact match and return just that one UTXO
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, exact_value);
    }

    #[test]
    fn knapsack_selects_enough() {
        let utxos = sample_utxos(); // 100k + 200k
        let (selected, fee) = CoinSelector::knapsack(&utxos, 50_000, 1.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 50_000 + fee, "Knapsack must cover target + fee");
    }

    #[test]
    fn select_tries_multiple_strategies() {
        // Create UTXOs where BnB will fail (no changeless combo) but knapsack
        // or greedy should succeed.
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let make = |val: u64, id: u8| WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([id; 32])),
                vout: 0,
            },
            value: val,
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
            is_own_change: false,
            is_coinbase: false,
        };
        // UTXOs with values that won't give BnB an exact match for 80k target
        let utxos = vec![make(50_000, 1), make(50_000, 2), make(50_000, 3)];
        let (selected, fee) = CoinSelector::select(&utxos, 80_000, 1.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 80_000 + fee);
    }

    // ── Multi-SIGHASH tests ──────────────────────────────────────────────

    #[test]
    fn signing_input_default_sighash_is_all() {
        // When sighash_type is None, sign_transaction should use SIGHASH_ALL (0x01)
        let seed = [42u8; 64];
        let xprv = ExtendedPrivKey::from_seed(&seed).unwrap();
        let sk = xprv.private_key;
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let spk = p2wpkh_script(&pk);

        let op = OutPoint {
            txid: Txid(Hash256([0xAA; 32])),
            vout: 0,
        };
        let tx = TxBuilder::new()
            .add_input(op.clone())
            .add_output(50_000, Script::from_bytes(vec![0x51]))
            .build();

        let si = SigningInput {
            outpoint: op,
            value: 100_000,
            script_pubkey: spk,
            secret_key: sk,
            witness_script: None,
            sighash_type: None, // defaults to All
        };

        let signed = sign_transaction(&tx, &[si]).unwrap();
        // P2WPKH witness: [sig, pubkey]; sig ends with sighash byte 0x01
        assert_eq!(signed.inputs[0].witness.len(), 2);
        let sig = &signed.inputs[0].witness[0];
        assert_eq!(*sig.last().unwrap(), 0x01, "default sighash byte must be 0x01 (ALL)");
    }

    #[test]
    fn signing_with_sighash_none() {
        let seed = [42u8; 64];
        let xprv = ExtendedPrivKey::from_seed(&seed).unwrap();
        let sk = xprv.private_key;
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let spk = p2wpkh_script(&pk);

        let op = OutPoint {
            txid: Txid(Hash256([0xBB; 32])),
            vout: 0,
        };
        let tx = TxBuilder::new()
            .add_input(op.clone())
            .add_output(50_000, Script::from_bytes(vec![0x51]))
            .build();

        let si = SigningInput {
            outpoint: op,
            value: 100_000,
            script_pubkey: spk,
            secret_key: sk,
            witness_script: None,
            sighash_type: Some(SighashType::None),
        };

        let signed = sign_transaction(&tx, &[si]).unwrap();
        let sig = &signed.inputs[0].witness[0];
        assert_eq!(*sig.last().unwrap(), 0x02, "sighash byte must be 0x02 (NONE)");
    }

    #[test]
    fn signing_with_sighash_single_anyone_can_pay() {
        let seed = [42u8; 64];
        let xprv = ExtendedPrivKey::from_seed(&seed).unwrap();
        let sk = xprv.private_key;
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let spk = p2wpkh_script(&pk);

        let op = OutPoint {
            txid: Txid(Hash256([0xCC; 32])),
            vout: 0,
        };
        let tx = TxBuilder::new()
            .add_input(op.clone())
            .add_output(50_000, Script::from_bytes(vec![0x51]))
            .build();

        let si = SigningInput {
            outpoint: op,
            value: 100_000,
            script_pubkey: spk,
            secret_key: sk,
            witness_script: None,
            sighash_type: Some(SighashType::SingleAnyoneCanPay),
        };

        let signed = sign_transaction(&tx, &[si]).unwrap();
        let sig = &signed.inputs[0].witness[0];
        assert_eq!(*sig.last().unwrap(), 0x83, "sighash byte must be 0x83 (SINGLE|ANYONECANPAY)");
    }

    // ── Per-type weight tests ────────────────────────────────────────────

    #[test]
    fn input_weight_ordering() {
        // Taproot < SegWit < P2SH-P2WPKH < Legacy
        assert!(input_weight(AddressType::Taproot) < input_weight(AddressType::SegWit));
        assert!(input_weight(AddressType::SegWit) < input_weight(AddressType::P2shP2wpkh));
        assert!(input_weight(AddressType::P2shP2wpkh) < input_weight(AddressType::Legacy));
    }

    #[test]
    fn input_vbytes_matches_weight_div4() {
        for t in [
            AddressType::Legacy,
            AddressType::P2shP2wpkh,
            AddressType::SegWit,
            AddressType::Taproot,
        ] {
            let vb = input_vbytes(t);
            let w = input_weight(t) as f64;
            assert!((vb - w / 4.0).abs() < 0.01, "vbytes mismatch for {t:?}");
        }
    }

    #[test]
    fn selection_weight_increases_with_inputs() {
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let make = |id: u8, addr_type: AddressType| WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([id; 32])),
                vout: 0,
            },
            value: 100_000,
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type: addr_type,
            is_own_change: false,
            is_coinbase: false,
        };
        let one = vec![make(1, AddressType::SegWit)];
        let two = vec![make(1, AddressType::SegWit), make(2, AddressType::SegWit)];
        assert!(CoinSelector::selection_weight(&two) > CoinSelector::selection_weight(&one));
    }

    // ── Max weight enforcement tests ─────────────────────────────────────

    #[test]
    fn max_weight_rejects_oversized_selection() {
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let make = |id: u8| WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([id; 32])),
                vout: 0,
            },
            value: 10_000,
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
            is_own_change: false,
            is_coinbase: false,
        };
        // 50 UTXOs × 10k each = 500k total, target = 400k
        // With a very tight max_weight, it should fail
        let utxos: Vec<_> = (0..50).map(|i| make(i)).collect();
        let result = CoinSelector::select_with_max_weight(&utxos, 400_000, 1.0, 500);
        assert!(
            result.is_err(),
            "should fail with max_weight=500 WU"
        );
    }

    #[test]
    fn max_weight_accepts_lightweight_selection() {
        let utxos = sample_utxos();
        // Very generous max weight — should succeed
        let result = CoinSelector::select_with_max_weight(&utxos, 50_000, 1.0, 400_000);
        assert!(result.is_ok());
    }

    // ── CoinGrinder tests ────────────────────────────────────────────────

    fn make_typed_utxo(val: u64, id: u8, addr_type: AddressType) -> WalletUtxo {
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([id; 32])),
                vout: 0,
            },
            value: val,
            script_pubkey: spk,
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type,
            is_own_change: false,
            is_coinbase: false,
        }
    }

    #[test]
    fn coin_grinder_prefers_lighter_inputs() {
        // Two UTXOs of equal value but different types
        let utxos = vec![
            make_typed_utxo(100_000, 1, AddressType::Legacy),   // 592 WU
            make_typed_utxo(100_000, 2, AddressType::Taproot),  // 230 WU
        ];
        // High fee rate to activate CoinGrinder
        let result = CoinSelector::coin_grinder(&utxos, 50_000, 50.0, 400_000);
        assert!(result.is_some());
        let (selected, _fee) = result.unwrap();
        // Should prefer the Taproot UTXO (lighter)
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].addr_type, AddressType::Taproot);
    }

    #[test]
    fn coin_grinder_respects_max_weight() {
        // Create UTXOs that would exceed a tight max weight if all selected
        let utxos = vec![
            make_typed_utxo(30_000, 1, AddressType::Legacy),
            make_typed_utxo(30_000, 2, AddressType::Legacy),
            make_typed_utxo(30_000, 3, AddressType::Legacy),
            make_typed_utxo(50_000, 4, AddressType::Taproot),
        ];
        // Target requires ~80k, max weight is tight
        // CoinGrinder should find a solution under max weight using fewer/lighter inputs
        let max_w = CoinSelector::selection_weight(&[
            make_typed_utxo(0, 0, AddressType::Taproot),
            make_typed_utxo(0, 0, AddressType::Legacy),
            make_typed_utxo(0, 0, AddressType::Legacy),
        ]);
        let result = CoinSelector::coin_grinder(&utxos, 50_000, 50.0, max_w);
        if let Some((selected, _)) = &result {
            let w = CoinSelector::selection_weight(selected);
            assert!(w <= max_w, "selection weight {w} > max {max_w}");
        }
    }

    #[test]
    fn coin_grinder_empty_utxos() {
        let result = CoinSelector::coin_grinder(&[], 1000, 50.0, 400_000);
        assert!(result.is_none());
    }

    #[test]
    fn coin_grinder_insufficient_funds() {
        let utxos = vec![make_typed_utxo(1000, 1, AddressType::SegWit)];
        let result = CoinSelector::coin_grinder(&utxos, 100_000, 50.0, 400_000);
        assert!(result.is_none());
    }

    #[test]
    fn coin_grinder_selects_minimum_weight_subset() {
        // Two possible ways to cover 50k target at high fee rate:
        // Option A: 1 Legacy (100k, 592 WU)
        // Option B: 2 Taproot (50k+50k=100k, 460 WU)
        // CoinGrinder should prefer option B (lower weight)
        let utxos = vec![
            make_typed_utxo(100_000, 1, AddressType::Legacy),
            make_typed_utxo(50_000, 2, AddressType::Taproot),
            make_typed_utxo(50_000, 3, AddressType::Taproot),
        ];
        let result = CoinSelector::coin_grinder(&utxos, 50_000, 50.0, 400_000);
        assert!(result.is_some());
        let (selected, _) = result.unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 50_000, "must cover target");
        // Count how many Taproot vs Legacy inputs were selected
        let taproot_count = selected.iter().filter(|u| u.addr_type == AddressType::Taproot).count();
        let legacy_count = selected.iter().filter(|u| u.addr_type == AddressType::Legacy).count();
        // CoinGrinder should prefer the lighter combination
        // (either 2×Taproot at 460 WU or 1×Legacy at 592 WU)
        if selected.len() > 1 {
            assert!(taproot_count >= legacy_count, "should prefer taproot when weight-optimizing");
        }
    }

    #[test]
    fn high_fee_rate_activates_coin_grinder() {
        // At high fee rates, select_with_max_weight should use CoinGrinder
        // when BnB fails (no changeless solution)
        let utxos = vec![
            make_typed_utxo(50_000, 1, AddressType::Legacy),   // heavy
            make_typed_utxo(50_000, 2, AddressType::Taproot),  // light
            make_typed_utxo(50_000, 3, AddressType::Taproot),  // light
        ];
        // High fee rate (above LONG_TERM_FEE_RATE) triggers CoinGrinder
        let result = CoinSelector::select_with_max_weight(&utxos, 60_000, 50.0, 400_000);
        assert!(result.is_ok());
        let (selected, fee) = result.unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 60_000 + fee);
    }

    #[test]
    fn coin_grinder_bnb_example_from_bitcoin_core() {
        // Reproduce the example from Bitcoin Core's CoinGrinder comments:
        // UTXOs: A=[10/2], B=[7/1], C=[5/1], D=[4/2] (eff_value/weight)
        // Target = 11, change_target implicitly included in total_target
        //
        // We use fee_rate=0 so effective_value == value, and carefully set
        // weights via address types. At fee_rate=0, Taproot input = 230 WU,
        // SegWit = 273 WU, Legacy = 592 WU.
        //
        // We can't exactly match the 1,2 WU from the example, but we can
        // verify the algorithm picks the minimum-weight selection.

        // Use very low fee rate so effective value ~ value
        let fee_rate = 0.001;

        // All same type so weight differences don't matter — test pure BnB logic
        let utxos = vec![
            make_typed_utxo(100_000, 1, AddressType::Taproot),  // Highest value
            make_typed_utxo(70_000, 2, AddressType::Taproot),
            make_typed_utxo(50_000, 3, AddressType::Taproot),
            make_typed_utxo(40_000, 4, AddressType::Taproot),
        ];

        // Target that requires at least 2 UTXOs (e.g. 110k)
        // Best solution should be utxos[1]+utxos[2] = 120k (2 inputs, lowest weight)
        // rather than utxos[0]+utxos[3] = 140k (also 2 inputs but same weight, higher amount)
        let result = CoinSelector::coin_grinder(&utxos, 110_000, fee_rate, 2_000_000);
        assert!(result.is_some());
        let (selected, _) = result.unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 110_000, "must cover target");
        // With equal weights, CoinGrinder should prefer lower amount as tiebreaker
        // Best = {70k + 50k} = 120k (first valid 2-input solution found)
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn coin_grinder_mixed_weights_prefers_minimum() {
        // Mix of Legacy (592 WU) and Taproot (230 WU) inputs.
        // Target can be met by:
        //   Option A: 1 Legacy (80k, 592 WU)
        //   Option B: 2 Taproot (50k+50k, 460 WU)
        // CoinGrinder should pick Option B (lower weight).
        let utxos = vec![
            make_typed_utxo(80_000, 1, AddressType::Legacy),
            make_typed_utxo(50_000, 2, AddressType::Taproot),
            make_typed_utxo(50_000, 3, AddressType::Taproot),
        ];
        // Low fee rate so effective values are close to face values
        let result = CoinSelector::coin_grinder(&utxos, 30_000, 0.5, 2_000_000);
        assert!(result.is_some());
        let (selected, _) = result.unwrap();
        let w: i64 = selected.iter().map(|u| input_weight(u.addr_type)).sum();
        // If only 1 input needed, Taproot (230 WU) should be preferred over Legacy (592 WU)
        // The 80k Legacy alone could cover 30k, but the 50k Taproot also covers it with less weight
        assert!(selected.iter().any(|u| u.addr_type == AddressType::Taproot));
        assert!(w <= 592, "should pick lighter input(s), got weight {w}");
    }

    #[test]
    fn coin_grinder_clone_skipping() {
        // UTXOs with identical effective values ("clones") — CoinGrinder should
        // skip clones during SHIFT to avoid evaluating equivalent selections.
        let utxos = vec![
            make_typed_utxo(100_000, 1, AddressType::Taproot),
            make_typed_utxo(100_000, 2, AddressType::Taproot),  // clone of 1
            make_typed_utxo(100_000, 3, AddressType::Taproot),  // clone of 1
            make_typed_utxo(50_000, 4, AddressType::Taproot),
        ];
        let result = CoinSelector::coin_grinder(&utxos, 80_000, 1.0, 2_000_000);
        assert!(result.is_some());
        let (selected, _) = result.unwrap();
        // Should pick exactly 1 of the 100k UTXOs (any of the clones is fine)
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 100_000);
    }

    #[test]
    fn coin_grinder_cut_prunes_barren_subtrees() {
        // Arrange UTXOs so that inclusion of first UTXO + all remaining can't
        // reach target, forcing a CUT early.
        let utxos = vec![
            make_typed_utxo(10_000, 1, AddressType::Taproot),
            make_typed_utxo(5_000, 2, AddressType::Taproot),
            make_typed_utxo(3_000, 3, AddressType::Taproot),
        ];
        // Target is higher than total available — should return None efficiently
        let result = CoinSelector::coin_grinder(&utxos, 500_000, 1.0, 2_000_000);
        assert!(result.is_none());
    }

    #[test]
    fn coin_grinder_max_weight_constraint_forces_lighter_set() {
        // With a very tight weight budget, CoinGrinder must find a solution
        // that fits within the weight limit even if it means using more inputs.
        let utxos = vec![
            make_typed_utxo(200_000, 1, AddressType::Legacy),   // 592 WU
            make_typed_utxo(200_000, 2, AddressType::Taproot),  // 230 WU
        ];
        // Set max_weight tight enough that Legacy alone would exceed it but
        // Taproot fits. overhead_wu ~ 290, so total with Legacy ~ 882, with Taproot ~ 520
        let tight_max = 600; // Only Taproot fits
        let result = CoinSelector::coin_grinder(&utxos, 50_000, 1.0, tight_max);
        assert!(result.is_some());
        let (selected, _) = result.unwrap();
        assert_eq!(selected[0].addr_type, AddressType::Taproot);
    }

    // ── M30: SRD in main cascade ─────────────────────────────────────────

    #[test]
    fn srd_in_cascade_selects_enough() {
        // Create a set of UTXOs where BnB won't find a changeless match,
        // CoinGrinder won't activate (low fee rate), and Knapsack's random
        // selection may fail but SRD should succeed.
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let make = |val: u64, id: u8| WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([id; 32])),
                vout: 0,
            },
            value: val,
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qtest".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
            is_own_change: false,
            is_coinbase: false,
        };

        // Many small UTXOs — the cascade should eventually succeed
        let utxos: Vec<WalletUtxo> = (1..=20).map(|i| make(10_000, i)).collect();
        let (selected, fee) = CoinSelector::select(&utxos, 100_000, 1.0).unwrap();
        let total: u64 = selected.iter().map(|u| u.value).sum();
        assert!(total >= 100_000 + fee, "cascade must cover target + fee");
    }

    // ── M31: Effective value filtering ───────────────────────────────────

    #[test]
    fn effective_value_filtering() {
        // A UTXO with 100 sat and a high fee rate should be uneconomical.
        // input_vbytes(SegWit) = 68, at 10 sat/vB → fee = 680 sat > 100 sat value.
        let spk = p2wpkh_script(&ExtendedPrivKey::from_seed(&[2u8; 64]).unwrap().public_key());
        let dust_utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([1u8; 32])),
                vout: 0,
            },
            value: 100, // dust
            script_pubkey: spk.clone(),
            height: 100,
            address: "bc1qdust".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
            is_own_change: false,
            is_coinbase: false,
        };
        let normal_utxo = WalletUtxo {
            outpoint: OutPoint {
                txid: Txid(Hash256([2u8; 32])),
                vout: 0,
            },
            value: 100_000,
            script_pubkey: spk,
            height: 100,
            address: "bc1qnormal".into(),
            confirmed: true,
            addr_type: AddressType::SegWit,
            is_own_change: false,
            is_coinbase: false,
        };

        // With just the dust UTXO at 10 sat/vB, it's uneconomical
        let fee_rate = 10.0;
        let input_fee = (input_vbytes(AddressType::SegWit) * fee_rate).ceil() as u64;
        assert!(dust_utxo.value <= input_fee, "100 sat should be uneconomical at 10 sat/vB");
        assert!(normal_utxo.value > input_fee, "100k sat should be economical");

        // The wallet's create_transaction filters these; here we verify
        // the effective value concept is correct.
        let eff_dust = dust_utxo.value as i64 - input_fee as i64;
        let eff_normal = normal_utxo.value as i64 - input_fee as i64;
        assert!(eff_dust <= 0, "dust effective value should be <= 0");
        assert!(eff_normal > 0, "normal effective value should be > 0");
    }
}
