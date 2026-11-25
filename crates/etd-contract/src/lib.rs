//! Public desktop protocol; never exposes kernel or transport types.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/etd.v1.rs"));
}
mod model;
pub use model::*;
pub use v1::{Desired, DesiredInstance, Hello, HostSnapshot, NetworkSpec, Role, Welcome};

pub const VERSION_MAJOR: u32 = 1;
pub const VERSION_MINOR: u32 = 0;
pub const FILE_DESCRIPTOR_SET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/host_descriptor.bin"));

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn hello_round_trip() {
        let hello = Hello {
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            build: "test".into(),
        };
        assert_eq!(
            Hello::decode(hello.encode_to_vec().as_slice()).unwrap(),
            hello
        );
        assert!(!FILE_DESCRIPTOR_SET.is_empty());
    }
}
