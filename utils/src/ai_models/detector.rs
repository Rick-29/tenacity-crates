use burn::{
    nn::{Gelu, Linear, LinearConfig, Sigmoid},
    prelude::{Backend, Module, Tensor},
};

use once_cell::sync::Lazy;
use std::collections::HashMap;

use super::TenacityModel;

static TRANSFORMER: Lazy<HashMap<char, usize>> = Lazy::new(create_transformer);
static TRANSFORMER_LEN: Lazy<usize> = Lazy::new(|| create_transformer().len() + 1);

fn create_transformer() -> HashMap<char, usize> {
    let chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-;:_{}[]|!#%&/()=?¡¿*/+";
    chars
        .chars()
        .enumerate()
        .fold(HashMap::new(), |mut acc, (index, char)| {
            acc.insert(char, index);
            acc
        })
}

#[derive(Module, Debug)]
pub struct Detector<B: Backend> {
    linear1: Linear<B>,
    linear2: Linear<B>,
    linear3: Linear<B>,
    gelu: Gelu,
    sigmoid: Sigmoid,
}

impl<B: Backend> TenacityModel<B> for Detector<B> {
    /// Create a new model.
    fn init(device: &B::Device) -> Self {
        let linear1 = LinearConfig::new(1024, 128).init(device);
        let linear2 = LinearConfig::new(128, 16).init(device);
        let linear3 = LinearConfig::new(16, 1).init(device);
        let gelu = Gelu::new();
        let sigmoid = Sigmoid::new();
        Self {
            linear1,
            linear2,
            linear3,
            gelu,
            sigmoid,
        }
    }
}

impl<B: Backend> Detector<B> {
    /// Forward pass of the model.
    pub fn forward(&self, x: Tensor<B, 2>) -> Tensor<B, 2> {
        self.sigmoid.forward(
            self.linear3.forward(
                self.gelu.forward(
                    self.linear2
                        .forward(self.gelu.forward(self.linear1.forward(x))),
                ),
            ),
        )
    }

    #[allow(clippy::single_range_in_vec_init)]
    pub fn tokenize(&self, msg: impl ToString) -> Tensor<B, 2> {
        let shape = 1024i64;
        let tensor = Tensor::<B, 1>::zeros(vec![shape], &Default::default());

        let data = msg
            .to_string()
            .chars()
            .map(|c| TRANSFORMER.get(&c).unwrap_or(&TRANSFORMER_LEN).to_owned() as f32)
            .collect::<Vec<f32>>();
        let msg_tensor = Tensor::<B, 1>::from_floats(data.as_slice(), &Default::default());
        if msg_tensor.dims()[0] > shape as usize {
            msg_tensor.slice([(0i64, shape)]).unsqueeze()
        } else {
            tensor
                .slice_assign([0..msg_tensor.dims()[0]], msg_tensor)
                .unsqueeze()
        }
    }
}
