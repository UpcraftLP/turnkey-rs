use std::fmt::Debug;

#[derive(Debug)]
struct HardwareBackedKeystore {}

const KEY_NAME: &str = "DPoP";

impl HardwareBackedKeystore {
    pub fn new() -> rootcause::Result<Self> {
        todo!()
    }
}
