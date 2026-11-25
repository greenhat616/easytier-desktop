use etd_ipc::BoxConn;
pub fn duplex(capacity: usize) -> (BoxConn, BoxConn) {
    let (left, right) = tokio::io::duplex(capacity);
    (Box::new(left), Box::new(right))
}
