use coppice::bond_tag::derive_v1_bond_tag;

use crate::inventory::{InventoryError, IronwoodViewingCapability, OwnedIronwoodNote};

/// The result of pure bond-note selection for a new registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedBondNote {
    pub output_id: crate::IronwoodOutputId,
    pub value_zat: u64,
    pub bond_tag: [u8; 32],
}

/// Selects the smallest eligible note whose value meets the minimum bond.
///
/// Selection is ordered by `(value_zat, output_id)`, so equal-value notes do
/// not depend on wallet iteration order. Existing active locks, including a
/// Coppice reservation, are not reusable for a new registration.
pub fn select_bond_note(
    notes: &[OwnedIronwoodNote],
    minimum_bond_value: u64,
    capability: IronwoodViewingCapability,
) -> Result<Option<SelectedBondNote>, InventoryError> {
    capability.require_nullifier_derivation()?;

    let mut selected: Option<SelectedBondNote> = None;
    for note in notes.iter().copied().filter(|note| {
        note.value_zat >= minimum_bond_value
            && note.spendable
            && note.freshness_eligible
            && !note.locked
    }) {
        let bond_tag = derive_v1_bond_tag(&note.nullifier).map_err(|source| {
            InventoryError::NonCanonicalNullifier {
                output_id: note.output_id,
                source,
            }
        })?;
        let candidate = SelectedBondNote {
            output_id: note.output_id,
            value_zat: note.value_zat,
            bond_tag,
        };
        if selected
            .map(|current| {
                (candidate.value_zat, candidate.output_id) < (current.value_zat, current.output_id)
            })
            .unwrap_or(true)
        {
            selected = Some(candidate);
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IronwoodOutputId;

    fn note(
        id: u8,
        value_zat: u64,
        locked: bool,
        spendable: bool,
        freshness_eligible: bool,
    ) -> OwnedIronwoodNote {
        OwnedIronwoodNote {
            output_id: IronwoodOutputId::new([id; 32], u32::from(id)),
            value_zat,
            nullifier: [id; 32],
            position: Some(u32::from(id)),
            locked,
            spendable,
            freshness_eligible,
        }
    }

    fn full_viewing() -> IronwoodViewingCapability {
        IronwoodViewingCapability::FullViewing
    }

    #[test]
    fn no_notes_and_all_below_minimum_have_no_candidate() {
        assert_eq!(select_bond_note(&[], 10, full_viewing()).unwrap(), None);
        assert_eq!(
            select_bond_note(&[note(1, 9, false, true, true)], 10, full_viewing()).unwrap(),
            None
        );
    }

    #[test]
    fn selects_smallest_qualifying_note_not_oldest_or_largest() {
        let notes = [
            note(1, 100, false, true, true),
            note(2, 20, false, true, true),
            note(3, 10, false, true, true),
        ];
        let selected = select_bond_note(&notes, 10, full_viewing())
            .unwrap()
            .unwrap();
        assert_eq!(selected.output_id, notes[2].output_id);
        assert_eq!(selected.value_zat, 10);
    }

    #[test]
    fn equal_value_selection_uses_output_id_tie_break() {
        let first = note(2, 10, false, true, true);
        let second = note(1, 10, false, true, true);
        let selected = select_bond_note(&[first, second], 10, full_viewing())
            .unwrap()
            .unwrap();
        assert_eq!(selected.output_id, second.output_id);
    }

    #[test]
    fn excludes_foreign_and_existing_coppice_locks() {
        let foreign = note(1, 10, true, true, true);
        let coppice = note(2, 11, true, true, true);
        assert_eq!(
            select_bond_note(&[foreign, coppice], 10, full_viewing()).unwrap(),
            None
        );
    }

    #[test]
    fn excludes_unavailable_and_freshness_ineligible_notes() {
        let notes = [
            note(1, 10, false, false, true),
            note(2, 11, false, true, false),
        ];
        assert_eq!(select_bond_note(&notes, 10, full_viewing()).unwrap(), None);
    }

    #[test]
    fn exact_minimum_is_accepted_and_tag_is_canonical_v1_derivation() {
        let selected = select_bond_note(&[note(7, 10, false, true, true)], 10, full_viewing())
            .unwrap()
            .unwrap();
        assert_eq!(selected.value_zat, 10);
        assert_eq!(
            selected.bond_tag,
            coppice::bond_tag::derive_v1_bond_tag(&[7; 32]).unwrap()
        );
    }

    #[test]
    fn incoming_only_fails_explicitly_even_with_no_candidates() {
        assert_eq!(
            select_bond_note(&[], 10, IronwoodViewingCapability::IncomingOnly),
            Err(InventoryError::InsufficientViewingCapability)
        );
    }

    #[test]
    fn output_id_order_is_independent_of_input_order() {
        let reversed = vec![
            note(2, 10, false, true, true),
            note(1, 10, false, true, true),
        ];
        let selected = select_bond_note(&reversed, 10, full_viewing())
            .unwrap()
            .unwrap();
        assert_eq!(selected.output_id, IronwoodOutputId::new([1; 32], 1));
    }
}
