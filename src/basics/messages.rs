/// The fixed portion of an ISO 7816-4 request APDU header.  This encodes the
/// class, instruction, and parameter bytes.
#[repr(C)]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct RequestHeader {
    /// The "class" byte.
    pub cla: u8,
    /// The "instruction" byte.
    pub ins: u8,
    /// The "parameter 1" byte.
    pub p1: u8,
    /// The "parameter 2" byte.
    pub p2: u8,
}

#[test]
fn check_request_header() {
    assert_eq!(::std::mem::size_of::<RequestHeader>(), 4);
}

#[derive(Debug)]
pub enum DecoderError {
    TooShort,
    InconsistentLength
}

#[derive(Debug)]
pub enum EncoderError {
    TooLong,
    NotRepresentable
}

/// A decoded ISO 7816-4 request APDU.  This represents a single APDU
/// in easy-to-use form.  To help avoid unnecessary allocations, the
/// payload is stored as a reference.
///
/// # Constraints
///
/// There are several constraints imposed by the encoding format:
///
/// * A short (extended == false) APDU can have at most 255 bytes of data and
///   a maximum response_length of 256.
/// * An extended APDU can have at most 65535 bytes of data and
///   a maximum response_length of 65536.
/// * An APDU with empty data and response_length == 0 must be short.  Blame
///   the bizarre encoding defined in ISO 7816-4: an empty extended APDU
///   would be encoded as ```CLA INS P1 P2 0```.  That would be ambiguous, as
///   it actually represents an empty short APDU with reponse_length == 256.
#[derive(Debug)]
pub struct RequestAPDU<'a> {
    /// The fixed header bytes.
    pub header: RequestHeader,
    /// The request payload.
    pub data: &'a [u8],
    /// Indicates whether this is an extended APDU.
    pub extended: bool,
    /// Indicates the expected length of the reply, referred to as "Le" in the
    /// spec.  According to ISO 7816-4, setting this to zero means that the
    /// entire reply is is requested.  In general, users should consult the
    /// documentation for the application protocol in use to determine what
    /// value should go here.
    pub response_length: u32,
}

impl<'a, 'b> PartialEq<RequestAPDU<'a>> for RequestAPDU<'b> {
    fn eq(&self, rhs: &RequestAPDU<'a>) -> bool {
        return self.header == rhs.header && self.data == rhs.data && self.extended == rhs.extended && self.response_length == rhs.response_length;
    }
}

pub type DecoderResult<'a> = Result<RequestAPDU<'a>, DecoderError>;
pub type EncoderResult = Result<Vec<u8>, EncoderError>;

fn read_le16(data: &[u8]) -> u16 {
    ((data[0] as u16) << 8) | data[1] as u16
}

fn read_extval(data: &[u8]) -> u32 {
    let raw = read_le16(data);
    if raw == 0 { 65536 } else { raw as u32 }
}

fn read_shortval(data: u8) -> u32 {
    if data == 0 { 256 } else { data as u32 }
}

/// Decodes an ISO 7816-4 request APDU.
///
/// To avoid unnecessary allocations, the returned `RequestAPDU` references
/// the provided input buffer.
///
/// Keep in mind that the APDU format is not a prefix code.  There is no way
/// to look at a long stream of bytes that is known to start with an APDU and
/// find the end of that APDU.
///
/// # Errors
///
/// Decoding will fail if the input buffer does not contain a valid APDU.
pub fn decode (buffer: &[u8]) -> DecoderResult {
    if buffer.len() < 4 {
        return Result::Err(DecoderError::TooShort);
    }

    let header = RequestHeader{
        cla: buffer[0], ins: buffer[1], p1: buffer[2], p2: buffer[3]
    };

    let body = &buffer[4..];

    let (data, extended, response_length) = match body.len() {
        // No body: case 1
        0 => (body, false, 0),

        // One byte: case 2S
        1 => (&body[0..0], false, read_shortval(body[0])),

        // First byte nonzero: 3S or 4S
        _ if body[0] != 0 => {
            let lc = body[0] as usize;
            if body.len() == lc + 1 {
                // Only enough room for data
                (&body[1 .. lc+1], false, 0)
            } else if body.len() == lc + 2 {
                // One extra byte for Le
                (&body[1 .. lc+1], false, read_shortval(body[lc + 1]))
            } else {
                return Result::Err(DecoderError::InconsistentLength)
            }
        }

        // First byte zero, more than one byte: extended
        _ if body[0] == 0 => {
            if body.len() == 3 {
                // Three bytes, first byte zero: case 2E
                (&body[1..1], true, read_extval(&body[1..3]))
            } else if body.len() > 3 {
                // There is at least one byte of data (Lc == Le == 0 is not
                // representable as an extended APDU).
                let lc = read_extval(&body[1..3]) as usize;
                if body.len() == lc + 3 {
                    // Only enough room for data
                    (&body[3 .. lc+3], true, 0)
                } else if body.len() == lc + 5 {
                    // Two extra bytes from Le
                    (&body[3 .. lc+3], true, read_extval(&body[lc+3 .. lc+5]))
                } else {
                    return Result::Err(DecoderError::InconsistentLength)
                }
            } else {
                return Result::Err(DecoderError::InconsistentLength)
            }
        }

        _ => panic!("")
    };

    Result::Ok(RequestAPDU {
        header: header,
        data: data,
        extended: extended,
        response_length: response_length,
    })
}

fn push_shortval(buf: &mut Vec<u8>, val: u32) {
    assert!(val > 0 && val <= 256);
    buf.push(if val == 256 { 0 } else { val as u8 });
}

fn encode_short(request: &RequestAPDU) -> EncoderResult {
    let mut len = 4;
    if request.data.len() > 0 {
        if request.data.len() > 255 {
            return Result::Err(EncoderError::TooLong);
        } else {
            len = len + 1;
        }
    }

    if request.response_length != 0 {
        if request.response_length > 256 {
            return Result::Err(EncoderError::NotRepresentable);
        } else {
            len = len + 1;
        }
    }
    let len = len;  // We're done computing len.

    let mut buf = Vec::<u8>::with_capacity(len);
    buf.extend([request.header.cla, request.header.ins,
                request.header.p1, request.header.p2].iter());

    // This mess is, by itself, unambiguously decodable (if rather messily).
    // It also never pushes a zero byte first for a message of length greater
    // than 5, which lets us distinguish it from the extended case.

    if request.data.len() != 0 {
        push_shortval(&mut buf, request.data.len() as u32);
        buf.extend_from_slice(request.data);
    }

    if request.response_length != 0 {
        push_shortval(&mut buf, request.response_length as u32);
    }

    Result::Ok(buf)
}

fn push_extval(buf: &mut Vec<u8>, val: u32) {
    assert!(val > 0 && val <= 65536);
    let coded = if val == 65536 { 0 } else { val as u16 };
    buf.push((coded >> 8) as u8);
    buf.push((coded & 0xFF) as u8);
}

fn encode_extended(request: &RequestAPDU) -> EncoderResult {
    if request.data.is_empty() && request.response_length == 0 {
        // Empty requests with expected response length 0 are only
        // representable as short APDUs, not as extended APDUs.
        return Result::Err(EncoderError::NotRepresentable);
    }

    let mut len = 5;
    if request.data.len() > 0 {
        if request.data.len() > 65535 {
            return Result::Err(EncoderError::TooLong);
        } else {
            len = len + 2;
        }
    }

    if request.response_length != 0 {
        if request.response_length > 65536 {
            return Result::Err(EncoderError::NotRepresentable);
        } else {
            len = len + 2;
        }
    }
    let len = len;  // We're done computing len.

    let mut buf = Vec::<u8>::with_capacity(len);
    buf.extend([request.header.cla, request.header.ins,
                request.header.p1, request.header.p2, 0].iter());

    if request.data.len() != 0 {
        push_extval(&mut buf, request.data.len() as u32);
        buf.extend_from_slice(request.data);
    }

    if request.response_length != 0 {
        push_extval(&mut buf, request.response_length as u32);
    }

    Result::Ok(buf)
}

pub fn encode(request: &RequestAPDU) -> EncoderResult {
    if request.extended { encode_extended(request) } else { encode_short(request) }
}

#[cfg(test)]
fn make_test_buf(len: usize) -> Vec<u8> {
    let mut ret = Vec::with_capacity(len);
    for i in 0..len {
        ret.push((i as u8).wrapping_add(50u8));
    }

    ret
}

#[cfg(test)]
fn roundtrip_req(req: &RequestAPDU) {
    let enc = encode(&req).expect(&format!("failed to encode:\n{:?}", *req));
    let dec = decode(&enc).expect(&format!("failed to decode:\n{:?}\n\nwhich we got by encoding:\n{:?}", enc, *req));
    if *req != dec { println!("encoded version was:\n{:?}", enc); }
    assert_eq!(*req, dec);
}

#[test]
fn encode_and_decode_short() {
    let header = RequestHeader{ cla: 0xfe, ins: 0xfd, p1: 0xfc, p2: 0xfb };

    for len in 0..256 {
        roundtrip_req(&RequestAPDU {
            header: header, data: &make_test_buf(len),
            extended: false, response_length: 0 });
    }

    for len in 0..257 {
        roundtrip_req(&RequestAPDU {
            header: header, data: &make_test_buf(0),
            extended: false, response_length: len as u32 });
    }

    for lc in [0, 1, 2, 254, 255].iter().cloned() {
        for le in [0, 1, 2, 254, 255, 256].iter().cloned() {
            roundtrip_req(&RequestAPDU {
                header: header, data: &make_test_buf(lc),
                extended: false, response_length: le as u32 });
        }
    }       
}

#[test]
fn encode_and_decode_extended() {
    let header = RequestHeader{ cla: 0xfe, ins: 0xfd, p1: 0xfc, p2: 0xfb };

    for lc in [0, 1, 2, 254, 255, 256, 257, 65534, 65535].iter().cloned() {
        for le in [0, 1, 2, 254, 255, 256, 257, 65534, 65535, 65535].iter().cloned() {
            if lc == 0 && le == 0 { continue; }
            roundtrip_req(&RequestAPDU {
                header: header, data: &make_test_buf(lc),
                extended: true, response_length: le as u32 });
        }
    }
}
