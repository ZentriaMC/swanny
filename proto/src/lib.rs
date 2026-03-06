pub mod zentria {
    pub mod swanny {
        pub mod v0 {
            tonic::include_proto!("zentria.swanny.v0");
        }
    }
}

pub use zentria::swanny::v0 as api;
