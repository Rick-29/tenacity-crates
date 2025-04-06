pub mod detector;

use burn::prelude::{Backend, Module};
use burn::record::{FullPrecisionSettings, NamedMpkFileRecorder, Recorder};

pub trait TenacityModel<B: Backend> {
    fn init(device: &B::Device) -> Self;
}
pub fn load_model<B: Backend, Net: Module<B> + TenacityModel<B>>(path: &str) -> Net {
    let device = Default::default();
    let record = NamedMpkFileRecorder::<FullPrecisionSettings>::default()
        .load(path.into(), &device)
        .expect("Should decode state successfully");

    Net::init(&device).load_record(record)
}
