use ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed::*, prelude::*},
    high_level::{load_cell, load_input, QueryIter},
};
use alloc::vec::Vec;
use super::hash;

pub fn has_input_by_lock_hash(lock_hash: [u8; 20]) -> bool {
    QueryIter::new(load_cell, Source::Input)
            .any(|cell| {
              hash::blake2b_160(cell.lock().as_slice())
            } == lock_hash)
}

pub fn position_input_by_lock_hash(lock_hash: [u8; 20]) -> Option<usize> {
    QueryIter::new(load_cell, Source::Input)
            .position(|cell| hash::blake2b_160(cell.lock().as_slice()) == lock_hash)
}

pub fn filter_cells_by_lock_hash(lock_hash: [u8; 20], source: Source) -> Option<Vec<CellOutput>> {
    let cells = QueryIter::new(load_cell, source)
            .filter(|cell| hash::blake2b_160(cell.lock().as_slice()) == lock_hash)
            .collect::<Vec<_>>();
    return if cells.len() == 0 {
      None
    } else {
      Some(cells)
    }
}

pub fn load_group_inputs() -> Vec<CellInput> {
    QueryIter::new(load_input, Source::GroupInput)
            .collect::<Vec<_>>()
}

pub fn calc_cells_capacity_sum(cells: Vec<CellOutput>) -> u64 {
  cells.into_iter().fold(0, |sum, c| sum + c.capacity().unpack())
}
