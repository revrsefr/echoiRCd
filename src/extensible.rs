//! Typed per-object metadata: a `TypeId`-keyed typemap. A module stores its own
//! concrete type and gets it back type-checked; the value is owned by the object
//! it hangs off, so it's dropped automatically when that object is — no registry,
//! no manual free, no dangling data.

use std::any::{Any, TypeId};
use std::collections::HashMap;

#[derive(Default)]
pub struct Extensible {
    map: HashMap<TypeId, Box<dyn Any + Send>>,
}

impl Extensible {
    pub fn get<T: Any + Send>(&self) -> Option<&T> {
        self.map
            .get(&TypeId::of::<T>())
            .and_then(|b| b.downcast_ref::<T>())
    }

    pub fn get_mut<T: Any + Send>(&mut self) -> Option<&mut T> {
        self.map
            .get_mut(&TypeId::of::<T>())
            .and_then(|b| b.downcast_mut::<T>())
    }

    pub fn set<T: Any + Send>(&mut self, value: T) {
        self.map.insert(TypeId::of::<T>(), Box::new(value));
    }

    /// Get the stored `T`, inserting `f()`'s value first if it's not there yet.
    pub fn get_or_insert_with<T: Any + Send>(&mut self, f: impl FnOnce() -> T) -> &mut T {
        self.map
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(f()))
            .downcast_mut::<T>()
            .expect("each TypeId keys exactly its own type")
    }

    pub fn take<T: Any + Send>(&mut self) -> Option<T> {
        self.map
            .remove(&TypeId::of::<T>())
            .and_then(|b| b.downcast::<T>().ok())
            .map(|b| *b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, PartialEq, Debug)]
    struct A(u32);
    struct B(&'static str);

    #[test]
    fn typed_storage_is_isolated_and_recoverable() {
        let mut e = Extensible::default();
        assert!(e.get::<A>().is_none());
        e.set(A(7));
        e.set(B("hi"));
        // two different types coexist, each recovered as itself
        assert_eq!(e.get::<A>(), Some(&A(7)));
        assert_eq!(e.get::<B>().map(|b| b.0), Some("hi"));
        e.get_mut::<A>().unwrap().0 += 1;
        assert_eq!(e.get::<A>(), Some(&A(8)));
        assert_eq!(e.take::<A>(), Some(A(8)));
        assert!(e.get::<A>().is_none());
        assert_eq!(*e.get_or_insert_with(|| A(100)), A(100));
    }
}
