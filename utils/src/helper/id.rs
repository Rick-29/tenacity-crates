use uuid::Uuid;

pub fn to_id(bytes: &[u8]) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, bytes)
}
