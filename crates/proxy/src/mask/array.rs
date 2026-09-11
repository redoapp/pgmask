use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{MaskError, FORMAT_BINARY, FORMAT_TEXT};

pub(super) const OID_NAME_ARRAY: u32 = 1003;
pub(super) const OID_TEXT_ARRAY: u32 = 1009;
pub(super) const OID_BPCHAR_ARRAY: u32 = 1014;
pub(super) const OID_VARCHAR_ARRAY: u32 = 1015;

const OID_NAME: u32 = 19;
const OID_TEXT: u32 = 25;
const MAX_ARRAY_BYTES: usize = 1024 * 1024;
const MAX_ARRAY_DIMENSIONS: i32 = 6;
const MAX_ARRAY_ELEMENTS: usize = 100_000;

pub(super) fn element_oid(array_oid: u32) -> Option<u32> {
    match array_oid {
        OID_NAME_ARRAY => Some(OID_NAME),
        OID_TEXT_ARRAY => Some(OID_TEXT),
        OID_BPCHAR_ARRAY => Some(super::OID_BPCHAR),
        OID_VARCHAR_ARRAY => Some(super::OID_VARCHAR),
        _ => None,
    }
}

pub(super) fn mask(
    array_oid: u32,
    format: i16,
    bytes: &Bytes,
    mut mask_element: impl FnMut(u32, i16, Bytes) -> Result<Bytes, MaskError>,
) -> Result<Bytes, MaskError> {
    if bytes.len() > MAX_ARRAY_BYTES {
        return Err(MaskError::ArrayLimitExceeded {
            configured: MAX_ARRAY_BYTES,
        });
    }
    let scalar_oid = element_oid(array_oid).ok_or(MaskError::Undecodable {
        type_oid: array_oid,
        format,
    })?;
    match format {
        FORMAT_TEXT => mask_text(array_oid, bytes, |value| {
            mask_element(scalar_oid, FORMAT_TEXT, Bytes::from(value))
        }),
        FORMAT_BINARY => mask_binary(array_oid, scalar_oid, bytes, |value| {
            mask_element(scalar_oid, FORMAT_BINARY, value)
        }),
        _ => Err(MaskError::Undecodable {
            type_oid: array_oid,
            format,
        }),
    }
}

fn mask_binary(
    array_oid: u32,
    scalar_oid: u32,
    bytes: &Bytes,
    mut mask_element: impl FnMut(Bytes) -> Result<Bytes, MaskError>,
) -> Result<Bytes, MaskError> {
    let undecodable = || MaskError::Undecodable {
        type_oid: array_oid,
        format: FORMAT_BINARY,
    };
    let mut input = bytes.as_ref();
    if input.remaining() < 12 {
        return Err(undecodable());
    }
    let dimensions = input.get_i32();
    let flags = input.get_i32();
    let encoded_element_oid = input.get_u32();
    if !(0..=MAX_ARRAY_DIMENSIONS).contains(&dimensions)
        || !matches!(flags, 0 | 1)
        || encoded_element_oid != scalar_oid
    {
        return Err(undecodable());
    }

    let dimension_bytes = usize::try_from(dimensions)
        .ok()
        .and_then(|count| count.checked_mul(8))
        .ok_or_else(undecodable)?;
    if input.remaining() < dimension_bytes {
        return Err(undecodable());
    }
    let mut decoded_dimensions = Vec::new();
    let mut elements = if dimensions == 0 { 0usize } else { 1usize };
    for _ in 0..dimensions {
        let length = input.get_i32();
        let lower_bound = input.get_i32();
        let length = usize::try_from(length).map_err(|_| undecodable())?;
        let upper_bound = i64::from(lower_bound)
            .checked_add(i64::try_from(length).map_err(|_| undecodable())?)
            .and_then(|exclusive| exclusive.checked_sub(1))
            .ok_or_else(undecodable)?;
        if length > 0 && i32::try_from(upper_bound).is_err() {
            return Err(undecodable());
        }
        elements = elements.checked_mul(length).ok_or_else(undecodable)?;
        if elements > MAX_ARRAY_ELEMENTS {
            return Err(MaskError::ArrayElementLimitExceeded {
                configured: MAX_ARRAY_ELEMENTS,
            });
        }
        decoded_dimensions.push((
            i32::try_from(length).map_err(|_| undecodable())?,
            lower_bound,
        ));
    }

    let mut has_nulls = false;
    let mut body = BytesMut::with_capacity(bytes.len());
    for _ in 0..elements {
        if input.remaining() < 4 {
            return Err(undecodable());
        }
        let length = input.get_i32();
        if length == -1 {
            has_nulls = true;
            body.put_i32(-1);
            continue;
        }
        let length = usize::try_from(length).map_err(|_| undecodable())?;
        if input.remaining() < length {
            return Err(undecodable());
        }
        let value = input.get(..length).ok_or_else(undecodable)?;
        let masked = mask_element(Bytes::copy_from_slice(value))?;
        input.advance(length);
        body.put_i32(i32::try_from(masked.len()).map_err(|_| undecodable())?);
        body.extend_from_slice(&masked);
        if body.len() > MAX_ARRAY_BYTES {
            return Err(MaskError::ArrayLimitExceeded {
                configured: MAX_ARRAY_BYTES,
            });
        }
    }
    if input.has_remaining() {
        return Err(undecodable());
    }
    if has_nulls && flags == 0 {
        return Err(undecodable());
    }
    let mut output = BytesMut::with_capacity(bytes.len());
    output.put_i32(dimensions);
    output.put_i32(flags);
    output.put_u32(scalar_oid);
    for (length, lower_bound) in decoded_dimensions {
        output.put_i32(length);
        output.put_i32(lower_bound);
    }
    output.extend_from_slice(&body);
    if output.len() > MAX_ARRAY_BYTES {
        return Err(MaskError::ArrayLimitExceeded {
            configured: MAX_ARRAY_BYTES,
        });
    }
    Ok(output.freeze())
}

fn mask_text(
    array_oid: u32,
    bytes: &Bytes,
    mut mask_element: impl FnMut(Vec<u8>) -> Result<Bytes, MaskError>,
) -> Result<Bytes, MaskError> {
    let mut parser = TextArrayParser {
        input: bytes,
        position: 0,
        elements: 0,
        output: Vec::with_capacity(bytes.len()),
        array_oid,
    };
    let expected_dimensions = parser.copy_dimensions()?;
    let actual_dimensions = parser.parse_array(1, &mut mask_element)?;
    if parser.position != bytes.len()
        || expected_dimensions
            .is_some_and(|expected| expected.as_slice() != actual_dimensions.as_slice())
        || parser.output.len() > MAX_ARRAY_BYTES
    {
        return Err(parser.undecodable());
    }
    Ok(Bytes::from(parser.output))
}

struct TextArrayParser<'a> {
    input: &'a [u8],
    position: usize,
    elements: usize,
    output: Vec<u8>,
    array_oid: u32,
}

impl TextArrayParser<'_> {
    fn undecodable(&self) -> MaskError {
        MaskError::Undecodable {
            type_oid: self.array_oid,
            format: FORMAT_TEXT,
        }
    }

    fn copy_dimensions(&mut self) -> Result<Option<Vec<usize>>, MaskError> {
        let start = self.position;
        let mut dimensions = Vec::new();
        while self.peek() == Some(b'[') {
            if dimensions.len()
                >= usize::try_from(MAX_ARRAY_DIMENSIONS).map_err(|_| self.undecodable())?
            {
                return Err(self.undecodable());
            }
            self.expect(b'[')?;
            let lower = self.parse_signed_integer()?;
            self.expect(b':')?;
            let upper = self.parse_signed_integer()?;
            self.expect(b']')?;
            let length = i64::from(upper)
                .checked_sub(i64::from(lower))
                .and_then(|difference| difference.checked_add(1))
                .and_then(|length| usize::try_from(length).ok())
                .ok_or_else(|| self.undecodable())?;
            dimensions.push(length);
        }
        if !dimensions.is_empty() {
            self.expect(b'=')?;
            let encoded_dimensions = self
                .input
                .get(start..self.position)
                .ok_or_else(|| self.undecodable())?;
            self.output.extend_from_slice(encoded_dimensions);
            Ok(Some(dimensions))
        } else {
            Ok(None)
        }
    }

    fn parse_signed_integer(&mut self) -> Result<i32, MaskError> {
        let number_start = self.position;
        if matches!(self.peek(), Some(b'+' | b'-')) {
            self.take()?;
        }
        let start = self.position;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.take()?;
        }
        if self.position == start {
            return Err(self.undecodable());
        }
        std::str::from_utf8(
            self.input
                .get(number_start..self.position)
                .ok_or_else(|| self.undecodable())?,
        )
        .ok()
        .and_then(|number| number.parse().ok())
        .ok_or_else(|| self.undecodable())
    }

    fn parse_array(
        &mut self,
        depth: i32,
        mask_element: &mut impl FnMut(Vec<u8>) -> Result<Bytes, MaskError>,
    ) -> Result<Vec<usize>, MaskError> {
        if depth > MAX_ARRAY_DIMENSIONS {
            return Err(self.undecodable());
        }
        self.expect(b'{')?;
        self.output.push(b'{');
        if self.peek() == Some(b'}') {
            self.expect(b'}')?;
            self.output.push(b'}');
            return Ok(vec![0]);
        }
        let mut child_shape: Option<Vec<usize>> = None;
        let mut length = 0usize;
        loop {
            let shape = if self.peek() == Some(b'{') {
                self.parse_array(
                    depth.checked_add(1).ok_or_else(|| self.undecodable())?,
                    mask_element,
                )?
            } else {
                self.parse_element(mask_element)?;
                Vec::new()
            };
            if child_shape
                .as_ref()
                .is_some_and(|expected| expected != &shape)
            {
                return Err(self.undecodable());
            }
            child_shape.get_or_insert(shape);
            length = length.saturating_add(1);
            match self.peek() {
                Some(b',') => {
                    self.expect(b',')?;
                    self.output.push(b',');
                }
                Some(b'}') => {
                    self.expect(b'}')?;
                    self.output.push(b'}');
                    let mut shape = vec![length];
                    shape.extend(child_shape.unwrap_or_default());
                    return Ok(shape);
                }
                _ => return Err(self.undecodable()),
            }
        }
    }

    fn parse_element(
        &mut self,
        mask_element: &mut impl FnMut(Vec<u8>) -> Result<Bytes, MaskError>,
    ) -> Result<(), MaskError> {
        self.elements = self.elements.saturating_add(1);
        if self.elements > MAX_ARRAY_ELEMENTS {
            return Err(MaskError::ArrayElementLimitExceeded {
                configured: MAX_ARRAY_ELEMENTS,
            });
        }
        let (value, quoted, escaped) = if self.peek() == Some(b'"') {
            (self.parse_quoted()?, true, false)
        } else {
            let (value, escaped) = self.parse_unquoted()?;
            (value, false, escaped)
        };
        if !quoted && !escaped && value.eq_ignore_ascii_case(b"NULL") {
            self.output.extend_from_slice(b"NULL");
            return Ok(());
        }
        let masked = mask_element(value)?;
        self.output.push(b'"');
        for byte in masked {
            if matches!(byte, b'"' | b'\\') {
                self.output.push(b'\\');
            }
            self.output.push(byte);
        }
        self.output.push(b'"');
        if self.output.len() > MAX_ARRAY_BYTES {
            return Err(MaskError::ArrayLimitExceeded {
                configured: MAX_ARRAY_BYTES,
            });
        }
        Ok(())
    }

    fn parse_quoted(&mut self) -> Result<Vec<u8>, MaskError> {
        self.expect(b'"')?;
        let mut value = Vec::new();
        loop {
            match self.peek() {
                Some(b'"') => {
                    self.expect(b'"')?;
                    return Ok(value);
                }
                Some(b'\\') => {
                    self.expect(b'\\')?;
                    value.push(self.take()?);
                }
                Some(byte) => {
                    self.take()?;
                    value.push(byte);
                }
                None => return Err(self.undecodable()),
            }
        }
    }

    fn parse_unquoted(&mut self) -> Result<(Vec<u8>, bool), MaskError> {
        let mut value = Vec::new();
        let mut escaped = false;
        loop {
            match self.peek() {
                Some(b',' | b'}') => break,
                Some(b'{' | b'"') | None if value.is_empty() => return Err(self.undecodable()),
                Some(b'{' | b'"') => return Err(self.undecodable()),
                Some(b'\\') => {
                    self.expect(b'\\')?;
                    escaped = true;
                    value.push(self.take()?);
                }
                Some(byte) => {
                    self.take()?;
                    value.push(byte);
                }
                None => break,
            }
        }
        if value.is_empty() {
            return Err(self.undecodable());
        }
        Ok((value, escaped))
    }

    fn expect(&mut self, expected: u8) -> Result<(), MaskError> {
        if self.take()? != expected {
            return Err(self.undecodable());
        }
        Ok(())
    }

    fn take(&mut self) -> Result<u8, MaskError> {
        let byte = self.peek().ok_or_else(|| self.undecodable())?;
        self.position = self
            .position
            .checked_add(1)
            .ok_or_else(|| self.undecodable())?;
        Ok(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use bytes::BufMut;

    fn identity_text(input: &'static [u8]) -> Result<Bytes, MaskError> {
        mask(
            OID_TEXT_ARRAY,
            FORMAT_TEXT,
            &Bytes::from_static(input),
            |_, _, value| Ok(value),
        )
    }

    #[test]
    fn text_arrays_preserve_shape_nulls_bounds_and_escaped_null_text() {
        let masked = identity_text(br#"[-1:0][4:5]={{NULL,\NULL},{"a,b","a\\b"}}"#).unwrap();
        assert_eq!(
            masked,
            Bytes::from_static(br#"[-1:0][4:5]={{NULL,"NULL"},{"a,b","a\\b"}}"#)
        );
        assert_eq!(identity_text(b"{}").unwrap(), Bytes::from_static(b"{}"));
    }

    #[test]
    fn malformed_text_arrays_fail_closed() {
        for input in [
            b"{a,{b}}".as_slice(),
            b"{{a},{b,c}}".as_slice(),
            b"[1:1]={a,b}".as_slice(),
            b"{\"unterminated}".as_slice(),
            b"{a,}".as_slice(),
            b"{a}trailing".as_slice(),
        ] {
            assert!(matches!(
                identity_text(input),
                Err(MaskError::Undecodable { .. })
            ));
        }
    }

    #[test]
    fn malformed_binary_arrays_fail_closed() {
        let mut wrong_element_oid = BytesMut::new();
        wrong_element_oid.put_i32(0);
        wrong_element_oid.put_i32(0);
        wrong_element_oid.put_u32(super::super::OID_VARCHAR);
        assert!(matches!(
            mask(
                OID_TEXT_ARRAY,
                FORMAT_BINARY,
                &wrong_element_oid.freeze(),
                |_, _, value| Ok(value)
            ),
            Err(MaskError::Undecodable { .. })
        ));

        let mut false_null_flag = BytesMut::new();
        false_null_flag.put_i32(1);
        false_null_flag.put_i32(0);
        false_null_flag.put_u32(OID_TEXT);
        false_null_flag.put_i32(1);
        false_null_flag.put_i32(1);
        false_null_flag.put_i32(-1);
        assert!(matches!(
            mask(
                OID_TEXT_ARRAY,
                FORMAT_BINARY,
                &false_null_flag.freeze(),
                |_, _, value| Ok(value)
            ),
            Err(MaskError::Undecodable { .. })
        ));

        let mut conservative_null_flag = BytesMut::new();
        conservative_null_flag.put_i32(1);
        conservative_null_flag.put_i32(1);
        conservative_null_flag.put_u32(OID_TEXT);
        conservative_null_flag.put_i32(1);
        conservative_null_flag.put_i32(1);
        conservative_null_flag.put_i32(1);
        conservative_null_flag.put_u8(b'x');
        assert!(mask(
            OID_TEXT_ARRAY,
            FORMAT_BINARY,
            &conservative_null_flag.freeze(),
            |_, _, value| Ok(value)
        )
        .is_ok());
    }

    #[test]
    fn input_and_encoded_output_limits_fail_closed() {
        let oversized = Bytes::from(vec![b'x'; MAX_ARRAY_BYTES.saturating_add(1)]);
        assert!(matches!(
            mask(OID_TEXT_ARRAY, FORMAT_TEXT, &oversized, |_, _, value| Ok(
                value
            )),
            Err(MaskError::ArrayLimitExceeded { .. })
        ));

        let elements = 40_000usize;
        let mut compact = String::with_capacity(elements.saturating_mul(3).saturating_add(2));
        compact.push('{');
        for index in 0..elements {
            if index > 0 {
                compact.push(',');
            }
            compact.push_str("\"\"");
        }
        compact.push('}');
        assert!(matches!(
            mask(
                OID_TEXT_ARRAY,
                FORMAT_TEXT,
                &Bytes::from(compact),
                |_, _, _| Ok(Bytes::from_static(b"0123456789abcdef0123456789abcdef"))
            ),
            Err(MaskError::ArrayLimitExceeded { .. })
        ));
    }
}
