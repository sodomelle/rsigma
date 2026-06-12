//! [`Confidence`](crate::core::Confidence) serialization.

use crate::core::Confidence;

impl serde::Serialize for Confidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.get())
    }
}

impl<'de> serde::Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <u8 as serde::Deserialize>::deserialize(deserializer)?;
        Confidence::new(raw).map_err(serde::de::Error::custom)
    }
}
