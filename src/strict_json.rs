use std::fmt;

use serde::de::{Error, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

pub(crate) fn value_from_slice(input: &[u8]) -> serde_json::Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

pub(crate) fn as_u64(value: &Value) -> Option<u64> {
    let number = value.as_number()?;
    if let Some(value) = number.as_i64() {
        return value.try_into().ok();
    }
    if let Some(value) = number.as_u64() {
        return Some(value);
    }
    let value = number.as_f64()?;
    (value.is_finite()
        && value.fract() == 0.0
        && (0.0..18_446_744_073_709_551_616.0).contains(&value))
    .then_some(value as u64)
}

pub(crate) fn as_u32(value: &Value) -> Option<u32> {
    as_u64(value)?.try_into().ok()
}

pub(crate) fn as_u16(value: &Value) -> Option<u16> {
    as_u64(value)?.try_into().ok()
}

pub(crate) fn as_i64(value: &Value) -> Option<i64> {
    let number = value.as_number()?;
    if let Some(value) = number.as_i64() {
        return Some(value);
    }
    if let Some(value) = number.as_u64() {
        return value.try_into().ok();
    }
    let value = number.as_f64()?;
    if value.is_finite()
        && value.fract() == 0.0
        && (-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&value)
    {
        Some(value as i64)
    } else {
        None
    }
}

pub(crate) fn as_i32(value: &Value) -> Option<i32> {
    let number = value.as_number()?;
    if let Some(value) = number.as_i64() {
        return value.try_into().ok();
    }
    if let Some(value) = number.as_u64() {
        return value.try_into().ok();
    }
    let value = number.as_f64()?;
    if value.is_finite()
        && value.fract() == 0.0
        && (-2_147_483_648.0..2_147_483_648.0).contains(&value)
    {
        Some(value as i32)
    } else {
        None
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        reject_nul(value)?;
        Ok(StrictValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        reject_nul(&value)?;
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or_default());
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::with_capacity(object.size_hint().unwrap_or_default());
        while let Some(key) = object.next_key::<String>()? {
            reject_nul::<A::Error>(&key)?;
            let value = object.next_value::<StrictValue>()?.0;
            if values.insert(key.clone(), value).is_some() {
                return Err(A::Error::custom(format!("duplicate object key: {key}")));
            }
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn reject_nul<E>(value: &str) -> Result<(), E>
where
    E: Error,
{
    if value.contains('\0') {
        return Err(E::custom("JSON strings must not contain NUL bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_keys_at_every_depth() {
        for input in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"outer":{"a":1,"a":2}}"#.as_slice(),
            br#"[{"a":1,"a":2}]"#.as_slice(),
        ] {
            assert!(value_from_slice(input).is_err());
        }
        value_from_slice(br#"[{"a":1},{"a":2}]"#).unwrap();
    }

    #[test]
    fn rejects_embedded_nul() {
        assert!(value_from_slice(br#"{"a":"x\u0000y"}"#).is_err());
        assert!(value_from_slice(br#"{"a\u0000b":1}"#).is_err());
    }

    #[test]
    fn integer_extraction_is_checked() {
        assert_eq!(as_i64(&serde_json::json!(5.0)), Some(5));
        assert_eq!(as_i64(&serde_json::json!(1.5)), None);
        assert_eq!(as_u32(&serde_json::json!(-1)), None);
        assert_eq!(as_u32(&serde_json::json!(4_294_967_296_u64)), None);
        assert_eq!(as_i32(&serde_json::json!(2_147_483_648_u64)), None);
    }
}
