//! Intermediate Representation (IR) for resolved ceremonies.
//!
//! The IR represents a ceremony after parsing and resolution:
//! - All references have been validated
//! - Execution order has been computed
//! - Parameter values have been merged with defaults
//! - Material sources have been validated (but not loaded)
//!
//! The IR is consumed by both the executor (for runtime) and
//! script generation (for paper output).

mod ceremony;
mod ids;

pub use ceremony::*;
pub use ids::*;

use indexmap::IndexMap;
use std::hash::Hash;

/// A symbol table mapping IDs to values.
///
/// Used for roles, sections, parameters, materials, and outputs.
/// Provides O(1) lookup by ID and iteration in insertion order.
#[derive(Debug, Clone)]
pub struct SymbolTable<Id, T> {
    items: IndexMap<Id, T>,
}

impl<Id: Eq + Hash + Clone, T> SymbolTable<Id, T> {
    /// Create a new empty symbol table.
    pub fn new() -> Self {
        Self {
            items: IndexMap::new(),
        }
    }

    /// Insert an item, returning an error if the ID already exists.
    pub fn insert(&mut self, id: Id, value: T) -> Result<(), Id> {
        if self.items.contains_key(&id) {
            return Err(id);
        }
        self.items.insert(id, value);
        Ok(())
    }

    /// Insert an item, overwriting if it already exists.
    pub fn insert_or_replace(&mut self, id: Id, value: T) {
        self.items.insert(id, value);
    }

    /// Get an item by ID.
    pub fn get(&self, id: &Id) -> Option<&T> {
        self.items.get(id)
    }

    /// Get a mutable reference to an item by ID.
    pub fn get_mut(&mut self, id: &Id) -> Option<&mut T> {
        self.items.get_mut(id)
    }

    /// Check if an ID exists in the table.
    pub fn contains(&self, id: &Id) -> bool {
        self.items.contains_key(id)
    }

    /// Iterate over all (ID, value) pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&Id, &T)> {
        self.items.iter()
    }

    /// Iterate over all values in insertion order.
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.items.values()
    }

    /// Iterate over all IDs in insertion order.
    pub fn keys(&self) -> impl Iterator<Item = &Id> {
        self.items.keys()
    }

    /// Get the number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl<Id: Eq + Hash + Clone, T> Default for SymbolTable<Id, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Id: Eq + Hash + Clone, T> FromIterator<(Id, T)> for SymbolTable<Id, T> {
    fn from_iter<I: IntoIterator<Item = (Id, T)>>(iter: I) -> Self {
        Self {
            items: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_table_basic_operations() {
        let mut table: SymbolTable<RoleId, String> = SymbolTable::new();

        // Insert succeeds for new ID.
        assert!(table.insert(RoleId::new("admin"), "Alice".into()).is_ok());

        // Insert fails for duplicate ID.
        assert!(table.insert(RoleId::new("admin"), "Bob".into()).is_err());

        // Get works.
        assert_eq!(table.get(&RoleId::new("admin")), Some(&"Alice".to_string()));
        assert_eq!(table.get(&RoleId::new("witness")), None);

        // Contains works.
        assert!(table.contains(&RoleId::new("admin")));
        assert!(!table.contains(&RoleId::new("witness")));
    }

    #[test]
    fn symbol_table_from_iterator() {
        let table: SymbolTable<StepId, u32> = vec![
            (StepId::new("step1"), 1),
            (StepId::new("step2"), 2),
            (StepId::new("step3"), 3),
        ]
        .into_iter()
        .collect();

        assert_eq!(table.len(), 3);
        assert_eq!(table.get(&StepId::new("step2")), Some(&2));
    }
}
