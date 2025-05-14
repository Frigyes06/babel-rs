//! Babel TLV parsing and serialization based on RFC 8966
//!
//! This module provides types and functions to work with Babel TLVs and sub-TLVs:
//! - `Tlv`: enum of all Babel TLV types (0‒10 plus Unknown)
//! - `SubTlv`: enum for sub-TLV types (Pad1, PadN, Unknown)
//! - `parse_all` / `parse`: routines to decode TLVs from a byte buffer
//! - `to_bytes`: routines to encode TLVs back to wire format
//!
//! References:
//! - <https://tools.ietf.org/html/rfc8966#section-4.3> (TLV types)
//! - <https://tools.ietf.org/html/rfc8966#section-4.7> (sub-TLVs)

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::vec;

/// A Babel TLV (Type-Length-Value), per RFC 8966 §4.3.
///
/// Each variant holds the TLV-specific fields. Unrecognized TLV types
/// are captured in the `Unknown` variant for forward compatibility.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Tlv {
    /// Pad1 (Type = 0): single-byte padding.
    Pad1,
    /// PadN (Type = 1): multi-byte padding.
    PadN { n: u8 },
    /// AckRequest (Type = 2): [Reserved(2), Opaque(2), Interval(2), Sub-TLVs...]
    AckRequest {
        opaque: u16,
        interval: u16,
        sub_tlvs: Vec<SubTlv>,
    },
    /// Ack (Type = 3): [Opaque(2), Sub-TLVs...]
    Ack { opaque: u16, sub_tlvs: Vec<SubTlv> },
    /// Hello (Type = 4): [Flags(2), Seqno(2), Interval(2), Sub-TLVs...]
    Hello {
        flags: u16,
        seqno: u16,
        interval: u16,
        sub_tlvs: Vec<SubTlv>,
    },
    /// IHU (Type = 5): [AE(1), Reserved(1), RxCost(2), Interval(2), Address?, Sub-TLVs...]
    Ihu {
        ae: u8,
        rxcost: u16,
        interval: u16,
        addr: Option<IpAddr>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// RouterId (Type = 6): [Reserved(2), RouterID(8), Sub-TLVs...]
    RouterId {
        router_id: [u8; 8],
        sub_tlvs: Vec<SubTlv>,
    },
    /// NextHop (Type = 7): [AE(1), Reserved(1), Address?, Sub-TLVs...]
    NextHop {
        ae: u8,
        addr: Option<IpAddr>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// Update (Type = 8): fields + prefix + sub-TLVs
    Update {
        ae: u8,
        flags: u8,
        plen: u8,
        omitted: u8,
        interval: u16,
        seqno: u16,
        metric: u16,
        prefix: Vec<u8>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// RouteRequest (Type = 9): [AE, PLen, Prefix, Sub-TLVs]
    RouteRequest {
        ae: u8,
        plen: u8,
        prefix: Vec<u8>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// SeqnoRequest (Type = 10): fields + router_id + prefix + sub-TLVs
    SeqnoRequest {
        ae: u8,
        plen: u8,
        seqno: u16,
        hop_count: u8,
        router_id: [u8; 8],
        prefix: Vec<u8>,
        sub_tlvs: Vec<SubTlv>,
    },
    /// Any other, unrecognized TLV: raw type byte + data.
    Unknown { tlv_type: u8, data: Vec<u8> },
}

/// A sub-TLV inside certain TLVs, per RFC 8966 §4.7.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SubTlv {
    /// Pad1 (SType = 0)
    Pad1,
    /// PadN (SType = 1)
    PadN { n: u8 },
    /// Any other, unrecognized sub-TLV: SType + data.
    Unknown { stype: u8, data: Vec<u8> },
}

impl Tlv {
    /// Parse all TLVs found in `buf`, stopping at EOF or error.
    ///
    /// Returns `Ok(Vec<Tlv>)` if parsing succeeds (possibly empty),
    /// or `Err(String)` on malformed data.
    pub fn parse_all(buf: &[u8]) -> Result<Vec<Tlv>, String> {
        let mut out = Vec::new();
        let mut cur = Cursor::new(buf);
        while let Ok(t) = Tlv::parse(&mut cur) {
            out.push(t);
        }
        Ok(out)
    }

    /// Parse a single TLV at the cursor position, advancing the cursor.
    ///
    /// Returns `Err("EOF")` on end-of-buffer, or other error strings on failure.
    pub fn parse(cur: &mut Cursor<&[u8]>) -> Result<Tlv, String> {
        let start = cur.position() as usize;
        let total = cur.get_ref().len();
        if start >= total {
            return Err("EOF".into());
        }
        // Read type byte
        let t = cur.read_u8().map_err(|e| e.to_string())?;
        if t < 2 {
            return Ok(Tlv::Pad1);
        }
        // Read length
        let length = cur.read_u8().map_err(|e| e.to_string())? as usize;
        let pos = cur.position() as usize;
        if pos + length > total {
            return Err("Length exceeds buffer".into());
        }
        // Extract payload slice
        let payload = cur.get_ref()[pos..pos + length].to_vec();
        cur.set_position((pos + length) as u64);

        // Dispatch by TLV type
        // Values 0 and >10 are treated as Pad1 (0) or Unknown respectively
        // t==0 handled earlier, so here t ∈ 1..=255 except 0
        let result: Tlv = match t {
            2 => {
                let mut p = Cursor::new(&payload);
                p.read_u16::<BigEndian>().map_err(|e| e.to_string())?; // reserved
                let opaque = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let interval = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                // let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::AckRequest {
                    opaque,
                    interval,
                    sub_tlvs: Vec::new(),
                }
            }
            3 => {
                let mut p = Cursor::new(&payload);
                let opaque = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                //let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::Ack {
                    opaque,
                    sub_tlvs: Vec::new(),
                }
            }
            4 => {
                let mut p = Cursor::new(&payload);
                let flags = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let seqno = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let interval = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                //let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::Hello {
                    flags,
                    seqno,
                    interval,
                    sub_tlvs: Vec::new(),
                }
            }
            5 => {
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                p.read_u8().map_err(|e| e.to_string())?;
                let rxcost = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let interval = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let addr = match ae {
                    1 => {
                        let mut o = [0; 4];
                        p.read_exact(&mut o).map_err(|e| e.to_string())?;
                        Some(IpAddr::V4(Ipv4Addr::from(o)))
                    }
                    2 | 3 => {
                        let mut o = [0; 16];
                        p.read_exact(&mut o).map_err(|e| e.to_string())?;
                        Some(IpAddr::V6(Ipv6Addr::from(o)))
                    }
                    _ => None,
                };
                //let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::Ihu {
                    ae,
                    rxcost,
                    interval,
                    addr,
                    sub_tlvs: Vec::new(),
                }
            }
            6 => {
                let mut p = Cursor::new(&payload);
                p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let mut router_id = [0; 8];
                p.read_exact(&mut router_id).map_err(|e| e.to_string())?;
                //let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::RouterId {
                    router_id,
                    sub_tlvs: Vec::new(),
                }
            }
            7 => {
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                p.read_u8().map_err(|e| e.to_string())?;
                let addr = match ae {
                    1 => {
                        let mut o = [0; 4];
                        p.read_exact(&mut o).map_err(|e| e.to_string())?;
                        Some(IpAddr::V4(Ipv4Addr::from(o)))
                    }
                    2 | 3 => {
                        let mut o = [0; 16];
                        p.read_exact(&mut o).map_err(|e| e.to_string())?;
                        Some(IpAddr::V6(Ipv6Addr::from(o)))
                    }
                    _ => None,
                };
                //let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::NextHop {
                    ae,
                    addr,
                    sub_tlvs: Vec::new(),
                }
            }
            8 => {
                // Update TLV: AE, Flags, PLen, Omitted, Interval, Seqno, Metric, Prefix, Sub-TLVs
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                let flags = p.read_u8().map_err(|e| e.to_string())?;
                let plen = p.read_u8().map_err(|e| e.to_string())?;
                let omitted = p.read_u8().map_err(|e| e.to_string())?;
                let interval = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let seqno = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let metric = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                // Calculate prefix length in bytes
                let prefix_len = ((plen as usize + 7) / 8).saturating_sub(omitted as usize);
                let mut prefix = vec![0u8; prefix_len];
                p.read_exact(&mut prefix).map_err(|e| e.to_string())?;
                // let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::Update {
                    ae,
                    flags,
                    plen,
                    omitted,
                    interval,
                    seqno,
                    metric,
                    prefix,
                    sub_tlvs: Vec::new(),
                }
            }
            9 => {
                // RouteRequest TLV: AE, PLen, Prefix, Sub-TLVs
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                let plen = p.read_u8().map_err(|e| e.to_string())?;
                let prefix_len = (plen as usize + 7) / 8;
                let mut prefix = vec![0u8; prefix_len];
                p.read_exact(&mut prefix).map_err(|e| e.to_string())?;
                //let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::RouteRequest {
                    ae,
                    plen,
                    prefix,
                    sub_tlvs: Vec::new(),
                }
            }
            10 => {
                // SeqnoRequest TLV: AE, PLen, Seqno, HopCount, Reserved, RouterID, Prefix, Sub-TLVs
                let mut p = Cursor::new(&payload);
                let ae = p.read_u8().map_err(|e| e.to_string())?;
                let plen = p.read_u8().map_err(|e| e.to_string())?;
                let seqno = p.read_u16::<BigEndian>().map_err(|e| e.to_string())?;
                let hop_count = p.read_u8().map_err(|e| e.to_string())?;
                p.read_u8().map_err(|e| e.to_string())?; // reserved
                let mut router_id = [0u8; 8];
                p.read_exact(&mut router_id).map_err(|e| e.to_string())?;
                let prefix_len = (plen as usize + 7) / 8;
                let mut prefix = vec![0u8; prefix_len];
                p.read_exact(&mut prefix).map_err(|e| e.to_string())?;
                //let subs = SubTlv::parse_list(&payload[p.position() as usize..])?;
                Tlv::SeqnoRequest {
                    ae,
                    plen,
                    seqno,
                    hop_count,
                    router_id,
                    prefix,
                    sub_tlvs: Vec::new(),
                }
            }
            other => Tlv::Unknown {
                tlv_type: other,
                data: payload.clone(),
            },
        };
        Ok(result)
    }

    /// Encode this Tlv into wire-format bytes: type, length, payload, sub-TLVs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Tlv::Pad1 => buf.push(0),
            Tlv::PadN { n } => {
                buf.push(1);
                buf.push(*n as u8);
                let mbz = vec![0; usize::from(*n)];
                buf.extend(mbz);
            }
            Tlv::AckRequest {
                opaque,
                interval,
                sub_tlvs,
            } => {
                buf.push(2);
                let body_len = 6 + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.extend(&[0; 2]);
                buf.write_u16::<BigEndian>(*opaque).unwrap();
                buf.write_u16::<BigEndian>(*interval).unwrap();
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Ack { opaque, sub_tlvs } => {
                buf.push(3);
                let body_len = 4 + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.write_u16::<BigEndian>(*opaque).unwrap();
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Hello {
                flags,
                seqno,
                interval,
                sub_tlvs,
            } => {
                buf.push(4);
                let body_len = 2 + 2 + 2 + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.write_u16::<BigEndian>(*flags).unwrap();
                buf.write_u16::<BigEndian>(*seqno).unwrap();
                buf.write_u16::<BigEndian>(*interval).unwrap();
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Ihu {
                ae,
                rxcost,
                interval,
                addr,
                sub_tlvs,
            } => {
                buf.push(5);
                let addr_len = match addr {
                    Some(IpAddr::V4(_)) => 4,
                    Some(IpAddr::V6(_)) => 16,
                    _ => 0,
                };
                let body_len =
                    1 + 1 + 2 + 2 + addr_len + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(0);
                buf.write_u16::<BigEndian>(*rxcost).unwrap();
                buf.write_u16::<BigEndian>(*interval).unwrap();
                if let Some(a) = addr {
                    match a {
                        IpAddr::V4(v4) => buf.extend(&v4.octets()),
                        IpAddr::V6(v6) => buf.extend(&v6.octets()),
                        _ => {}
                    }
                }
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::RouterId {
                router_id,
                sub_tlvs,
            } => {
                buf.push(6);
                let body_len = 2 + 8 + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.extend(&[0, 0]);
                buf.extend(router_id);
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::NextHop { ae, addr, sub_tlvs } => {
                buf.push(7);
                let addr_len = match addr {
                    Some(IpAddr::V4(_)) => 4,
                    Some(IpAddr::V6(_)) => 16,
                    _ => 0,
                };
                let body_len = 1 + 1 + addr_len + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(0);
                if let Some(a) = addr {
                    match a {
                        IpAddr::V4(v4) => buf.extend(&v4.octets()),
                        IpAddr::V6(v6) => buf.extend(&v6.octets()),
                        _ => {}
                    }
                }
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Update {
                ae,
                flags,
                plen,
                omitted,
                interval,
                seqno,
                metric,
                prefix,
                sub_tlvs,
            } => {
                buf.push(8);
                let body_len = 1
                    + 1
                    + 1
                    + 1
                    + 2
                    + 2
                    + 2
                    + prefix.len()
                    + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(*flags);
                buf.push(*plen);
                buf.push(*omitted);
                buf.write_u16::<BigEndian>(*interval).unwrap();
                buf.write_u16::<BigEndian>(*seqno).unwrap();
                buf.write_u16::<BigEndian>(*metric).unwrap();
                buf.extend(prefix);
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::RouteRequest {
                ae,
                plen,
                prefix,
                sub_tlvs,
            } => {
                buf.push(9);
                let body_len =
                    1 + 1 + prefix.len() + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(*plen);
                buf.extend(prefix);
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::SeqnoRequest {
                ae,
                plen,
                seqno,
                hop_count,
                router_id,
                prefix,
                sub_tlvs,
            } => {
                buf.push(10);
                let body_len = 1
                    + 1
                    + 2
                    + 1
                    + 1
                    + 8
                    + prefix.len()
                    + sub_tlvs.iter().map(|st| st.len()).sum::<usize>();
                buf.push(body_len as u8);
                buf.push(*ae);
                buf.push(*plen);
                buf.write_u16::<BigEndian>(*seqno).unwrap();
                buf.push(*hop_count);
                buf.push(0);
                buf.extend(router_id);
                buf.extend(prefix);
                for st in sub_tlvs {
                    buf.extend(st.to_bytes());
                }
            }
            Tlv::Unknown { tlv_type, data } => {
                buf.push(*tlv_type);
                buf.push(data.len() as u8);
                buf.extend(data);
            }
        }
        buf
    }
}

impl SubTlv {
    /// Parse a sequence of sub-TLVs from a slice.
    /// Stops at end-of-buffer; errors on malformed fields.
    /*
    pub fn parse_list(buf: &[u8]) -> Result<Vec<SubTlv>, String> {
        let mut out = Vec::new();
        let mut cur = Cursor::new(buf);
        while (cur.position() as usize) < buf.len() {
            let stype = cur.read_u8().map_err(|e| e.to_string())?;
            if stype == 0 {
                out.push(SubTlv::Pad1);
                continue;
            }
            let slen = cur.read_u8().map_err(|e| e.to_string())? as usize;
            let mut data = vec![0; slen];
            cur.read_exact(&mut data).map_err(|e| e.to_string())?;
            let s = match stype {
                1 => SubTlv::PadN { n },
                other => SubTlv::Unknown { stype: other, data },
            };
            out.push(s);
        }
        Ok(out)
    }
    */
    /// Compute the full wire length of this sub-TLV (including header).
    fn len(&self) -> usize {
        match self {
            SubTlv::Pad1 => 1,
            SubTlv::PadN { n } => usize::from(2 + n),
            SubTlv::Unknown { data, .. } => 2 + data.len(),
        }
    }

    /// Serialize this sub-TLV into wire-format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            SubTlv::Pad1 => buf.push(0),
            SubTlv::PadN { n } => {
                buf.push(1);
                buf.push(*n as u8);
                let mbz = vec![0; usize::from(*n)];
                buf.extend(mbz);
            }
            SubTlv::Unknown { stype, data } => {
                buf.push(*stype);
                buf.push(data.len() as u8);
                buf.extend(data);
            }
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad1() {
        let pad1 = Tlv::Pad1;
        assert_eq!(pad1.to_bytes(), vec![0])
    }

    #[test]
    fn test_padn() {
        let pad4 = Tlv::PadN { n: 4 };
        assert_eq!(pad4.to_bytes(), vec![1, 4, 0, 0, 0, 0])
    }

    #[test]
    fn test_ackreq() {
        let ackreq = Tlv::AckRequest {
            opaque: 278,
            interval: 400,
            sub_tlvs: Vec::new(),
        };
        assert_eq!(ackreq.to_bytes(), vec![2, 6, 0, 0, 1, 22, 1, 144])
    }

    // TODO! Implement tests for all Tlvs
}
