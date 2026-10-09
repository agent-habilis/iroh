//! A crate that implements a `PathSelector` can build synthetic paths and read the choice, with
//! the `selector-test-utils` feature. Without it the constructors are `pub(crate)` and a selector
//! outside iroh cannot be unit-tested.
#![cfg(feature = "selector-test-utils")]

use std::time::Duration;

use iroh::endpoint::{
    PathStats,
    transports::{
        Addr, FourTuple, PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
    },
};

/// Picks the first path it is given.
#[derive(Debug)]
struct First;

impl PathSelector for First {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let mut selection = PathSelection::none();
        if let Some(path) = ctx.paths().next() {
            selection.set(&path);
        }
        selection
    }
}

fn ip(port: u16) -> FourTuple {
    FourTuple::from_remote(Addr::Ip(std::net::SocketAddr::from(([127, 0, 0, 1], port))))
}

#[test]
#[allow(clippy::field_reassign_with_default)]
fn a_selector_outside_iroh_runs_on_synthetic_paths() {
    let (a, b) = (ip(1), ip(2));
    let mut stats = PathStats::default();
    stats.rtt = Duration::from_millis(5);
    let paths = vec![
        PathSelectionData::for_test(&a, Some(stats)),
        PathSelectionData::for_test(&b, None),
    ];
    let ctx = PathSelectionContext::for_test(None, paths);
    let selection = First.select(&ctx);
    assert_eq!(selection.selected_for_test(), Some(&a));
}
