//! Helpers shared by the integration tests.

#![allow(dead_code)]

use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};

/// The keys of the JSON object `text`, in the order they are written.
pub fn top_keys(text: &str) -> Vec<String> {
    struct Keys;

    impl<'de> Visitor<'de> for Keys {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Vec<String>, A::Error> {
            let mut keys = Vec::new();
            while let Some(key) = map.next_key::<String>()? {
                map.next_value::<IgnoredAny>()?;
                keys.push(key);
            }
            Ok(keys)
        }
    }

    serde_json::Deserializer::from_str(text)
        .deserialize_map(Keys)
        .expect("the text is a JSON object")
}
