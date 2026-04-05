use rete_core::Identity;
use rete_tokio::TokioNode;

/// Run an async test on a thread with 16MB stack.
///
/// In debug builds `Box::new(T::new())` may materialise the struct on the
/// stack before moving it to the heap, so we need a generous stack.
pub fn big_stack_test(f: fn()) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

/// Box-allocate a TokioNode to avoid stack overflow.
pub fn make_node(seed: &[u8]) -> Box<TokioNode> {
    let identity = Identity::from_seed(seed).unwrap();
    Box::new(TokioNode::new(identity, "rete", &["example", "v1"]).unwrap())
}
