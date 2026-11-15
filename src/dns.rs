#[cfg(feature = "ipset")]
use crate::ipset::IpsetAddCtx;
use std::net::IpAddr;

/// A borrowed DNS message view for hot-path parsing without copying packet data.
pub struct DnsView<'a> {
    pub bytes: &'a [u8],
}

impl<'a> DnsView<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        Some(Self { bytes })
    }

    pub fn get_id(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    pub fn get_rcode(&self) -> u16 {
        (u16::from_be_bytes([self.bytes[2], self.bytes[3]])) & 0x000F
    }

    pub fn is_good(&self) -> bool {
        self.is_cacheable()
    }

    pub fn is_cacheable(&self) -> bool {
        let flags = u16::from_be_bytes([self.bytes[2], self.bytes[3]]);
        let qr = (flags & 0x8000) != 0;
        let rcode = flags & 0x000F;
        let tc = (flags & 0x0200) != 0;
        qr && !tc && (rcode == 0 || rcode == 3)
    }

    pub fn is_acceptable_upstream_response(&self) -> bool {
        let flags = u16::from_be_bytes([self.bytes[2], self.bytes[3]]);
        let qr = (flags & 0x8000) != 0;
        let rcode = flags & 0x000F;
        qr && (rcode == 0 || rcode == 3)
    }

    pub fn is_truncated(&self) -> bool {
        (self.bytes[2] & 0x02) != 0
    }

    pub fn get_edns_max_payload(&self) -> u16 {
        let mut max_payload = 512;
        let q_end = match self.find_question_end() {
            Some(e) => e,
            None => return max_payload,
        };

        let mut pos = q_end;
        let an_count = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);
        let ns_count = u16::from_be_bytes([self.bytes[8], self.bytes[9]]);
        let ar_count = u16::from_be_bytes([self.bytes[10], self.bytes[11]]);

        for _ in 0..(an_count + ns_count) {
            pos = match self.skip_name(pos) {
                Some(p) => p,
                None => return max_payload,
            };
            if pos + 10 > self.bytes.len() {
                return max_payload;
            }
            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }

        for _ in 0..ar_count {
            if pos >= self.bytes.len() {
                break;
            }
            pos = match self.skip_name(pos) {
                Some(p) => p,
                None => break,
            };
            if pos + 10 > self.bytes.len() {
                break;
            }
            let atype = u16::from_be_bytes([self.bytes[pos], self.bytes[pos + 1]]);
            if atype == 41 {
                max_payload = u16::from_be_bytes([self.bytes[pos + 2], self.bytes[pos + 3]]);
                break;
            }
            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }
        max_payload.max(512)
    }

    pub fn find_question_end(&self) -> Option<usize> {
        if self.bytes.len() < 12 {
            return None;
        }
        let qd_count = u16::from_be_bytes([self.bytes[4], self.bytes[5]]);
        if qd_count == 0 {
            return Some(12);
        }
        let mut pos = 12;
        for _ in 0..qd_count {
            let name_end = self.skip_name(pos)?;
            pos = name_end + 4;
            if pos > self.bytes.len() {
                return None;
            }
        }
        Some(pos)
    }

    pub fn get_qname_and_type(&self) -> Option<(compact_str::CompactString, u16)> {
        if self.bytes.len() < 12 {
            return None;
        }
        let qd_count = u16::from_be_bytes([self.bytes[4], self.bytes[5]]);
        if qd_count == 0 {
            return None;
        }
        let mut pos = 12;
        let mut name = compact_str::CompactString::new("");
        let mut jumped = false;
        let mut jump_pos = 0;
        let mut jumps = 0;

        while pos < self.bytes.len() {
            let len = self.bytes[pos] as usize;
            if len == 0 {
                pos += 1;
                let final_pos = if jumped { jump_pos } else { pos };
                if final_pos + 4 > self.bytes.len() {
                    return None;
                }
                let qtype = u16::from_be_bytes([self.bytes[final_pos], self.bytes[final_pos + 1]]);
                if !name.is_empty() {
                    name.pop();
                }
                return Some((name, qtype));
            }

            if (len & 0xC0) == 0xC0 {
                if pos + 2 > self.bytes.len() {
                    return None;
                }
                let offset = ((len & 0x3F) << 8) | (self.bytes[pos + 1] as usize);
                if offset >= self.bytes.len() {
                    return None;
                }
                if !jumped {
                    jump_pos = pos + 2;
                    jumped = true;
                }
                jumps += 1;
                if jumps > 10 {
                    return None;
                }
                pos = offset;
                continue;
            }

            pos += 1;
            if pos + len > self.bytes.len() {
                return None;
            }
            name.push_str(std::str::from_utf8(&self.bytes[pos..pos + len]).ok()?);
            name.push('.');
            pos += len;
        }
        None
    }

    pub fn for_each_ip<F>(&self, mut f: F) -> Option<bool>
    where
        F: FnMut(IpAddr) -> bool,
    {
        let q_end = self.find_question_end()?;
        let mut pos = q_end;
        let answer_count = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);

        for _ in 0..answer_count {
            if pos >= self.bytes.len() {
                break;
            }
            pos = self.skip_name(pos)?;
            if pos + 10 > self.bytes.len() {
                break;
            }

            let atype = u16::from_be_bytes([self.bytes[pos], self.bytes[pos + 1]]);
            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlen > self.bytes.len() {
                break;
            }

            if atype == 1 && rdlen == 4 {
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    self.bytes[pos],
                    self.bytes[pos + 1],
                    self.bytes[pos + 2],
                    self.bytes[pos + 3],
                ));
                if f(ip) {
                    return Some(true);
                }
            } else if atype == 28 && rdlen == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.bytes[pos..pos + 16]);
                let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                if f(ip) {
                    return Some(true);
                }
            }
            pos += rdlen;
        }
        None
    }

    pub fn get_min_ttl(&self) -> u32 {
        let q_end = match self.find_question_end() {
            Some(e) => e,
            None => return 0,
        };
        let mut pos = q_end;
        let answer_count = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);
        let ns_count = u16::from_be_bytes([self.bytes[8], self.bytes[9]]);
        let mut min_ttl = u32::MAX;
        let mut found = false;

        for _ in 0..(answer_count + ns_count) {
            pos = match self.skip_name(pos) {
                Some(p) => p,
                None => break,
            };
            if pos + 10 > self.bytes.len() {
                break;
            }

            let rtype = u16::from_be_bytes([self.bytes[pos], self.bytes[pos + 1]]);
            if rtype != 41 {
                let ttl_pos = pos + 4;
                let ttl = u32::from_be_bytes([
                    self.bytes[ttl_pos],
                    self.bytes[ttl_pos + 1],
                    self.bytes[ttl_pos + 2],
                    self.bytes[ttl_pos + 3],
                ]);
                if ttl < min_ttl {
                    min_ttl = ttl;
                }
                found = true;
            }

            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }
        if found { min_ttl } else { 0 }
    }

    #[cfg(feature = "ipset")]
    pub fn add_ips(&self, ctx: &mut IpsetAddCtx) {
        self.for_each_ip(|ip| {
            ctx.add(ip);
            false // continue
        });
    }

    fn skip_name(&self, mut pos: usize) -> Option<usize> {
        while pos < self.bytes.len() {
            let b = self.bytes[pos];
            if b & 0xC0 == 0xC0 {
                return Some(pos + 2);
            }
            if b == 0 {
                return Some(pos + 1);
            }
            pos += (b as usize) + 1;
        }
        None
    }
}

/// A lightweight, zero-allocation DNS message parser/wrapper
pub struct DnsMessage {
    pub bytes: Vec<u8>,
}

impl DnsMessage {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        Some(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Takes ownership of an existing Vec without cloning.
    pub fn from_vec(bytes: Vec<u8>) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        Some(Self { bytes })
    }

    /// Returns the inner buffer without cloning.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn get_id(&self) -> u16 {
        if self.bytes.len() < 2 {
            return 0;
        }
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    pub fn get_rcode(&self) -> u16 {
        if self.bytes.len() < 4 {
            return 0;
        }
        (u16::from_be_bytes([self.bytes[2], self.bytes[3]])) & 0x000F
    }

    pub fn is_good(&self) -> bool {
        self.is_cacheable()
    }

    pub fn is_cacheable(&self) -> bool {
        if self.bytes.len() < 12 {
            return false;
        }
        let flags = u16::from_be_bytes([self.bytes[2], self.bytes[3]]);
        let qr = (flags & 0x8000) != 0;
        let rcode = flags & 0x000F;
        // TC (Truncated) responses are "technically" good for the protocol (triggers fallback),
        // but for our internal 'is_good' check (which decides if we cache it),
        // we only want full responses.
        let tc = (flags & 0x0200) != 0;
        qr && !tc && (rcode == 0 || rcode == 3) // NoError or NXDomain
    }

    pub fn is_acceptable_upstream_response(&self) -> bool {
        if self.bytes.len() < 12 {
            return false;
        }
        let flags = u16::from_be_bytes([self.bytes[2], self.bytes[3]]);
        let qr = (flags & 0x8000) != 0;
        let rcode = flags & 0x000F;
        qr && (rcode == 0 || rcode == 3)
    }

    pub fn is_truncated(&self) -> bool {
        if self.bytes.len() < 12 {
            return false;
        }
        (self.bytes[2] & 0x02) != 0
    }

    pub fn set_truncated(&mut self) {
        if self.bytes.len() < 12 {
            return;
        }
        self.bytes[2] |= 0x02;
    }

    pub fn get_edns_max_payload(&self) -> u16 {
        let mut max_payload = 512;
        let q_end = match self.find_question_end() {
            Some(e) => e,
            None => return max_payload,
        };

        let mut pos = q_end;
        let an_count = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);
        let ns_count = u16::from_be_bytes([self.bytes[8], self.bytes[9]]);
        let ar_count = u16::from_be_bytes([self.bytes[10], self.bytes[11]]);

        // Skip Answer and Authority sections
        for _ in 0..(an_count + ns_count) {
            pos = match self.skip_name(pos) {
                Some(p) => p,
                None => return max_payload,
            };
            if pos + 10 > self.bytes.len() {
                return max_payload;
            }
            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }

        // Look for OPT in Additional section
        for _ in 0..ar_count {
            if pos >= self.bytes.len() {
                break;
            }
            pos = match self.skip_name(pos) {
                Some(p) => p,
                None => break,
            };
            if pos + 10 > self.bytes.len() {
                break;
            }
            let atype = u16::from_be_bytes([self.bytes[pos], self.bytes[pos + 1]]);
            if atype == 41 {
                // OPT
                max_payload = u16::from_be_bytes([self.bytes[pos + 2], self.bytes[pos + 3]]);
                break;
            }
            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }
        max_payload.max(512)
    }

    pub fn truncate_to_size(&mut self, max_size: usize) {
        if self.bytes.len() <= max_size {
            return;
        }

        // Truncate logic: Try to keep header + question, and as many answers as fit.
        // For simplicity and safety (preventing partial RRs),
        // we can truncate to Header + Question and set TC bit.
        if let Some(q_end) = self.find_question_end()
            && q_end <= max_size
        {
            self.bytes.truncate(q_end);
            self.set_truncated();
            // Reset AN, NS, AR counts to 0 in header
            self.bytes[6..12].fill(0);
        }
    }

    pub fn set_empty_reply(&mut self) {
        if self.bytes.len() < 12 {
            return;
        }
        // Set QR=1, RA=1, RCODE=0
        self.bytes[2] |= 0x80;
        self.bytes[3] = (self.bytes[3] & 0x70) | 0x80; // Clear RCODE, set RA, preserve AD/CD/Z

        // Set Answer, Authority, Additional counts to 0
        self.bytes[6..12].fill(0);

        // Truncate to Header + Question
        if let Some(q_end) = self.find_question_end() {
            self.bytes.truncate(q_end);
        }
    }

    fn find_question_end(&self) -> Option<usize> {
        if self.bytes.len() < 12 {
            return None;
        }
        let qd_count = u16::from_be_bytes([self.bytes[4], self.bytes[5]]);
        if qd_count == 0 {
            return Some(12);
        }
        let mut pos = 12;
        for _ in 0..qd_count {
            let name_end = self.skip_name(pos)?;
            pos = name_end + 4;
            if pos > self.bytes.len() {
                return None;
            }
        }
        Some(pos)
    }

    pub fn get_qname_and_type(&self) -> Option<(compact_str::CompactString, u16)> {
        if self.bytes.len() < 12 {
            return None;
        }
        let qd_count = u16::from_be_bytes([self.bytes[4], self.bytes[5]]);
        if qd_count == 0 {
            return None;
        }
        let mut pos = 12;
        let mut name = compact_str::CompactString::new("");
        let mut jumped = false;
        let mut jump_pos = 0;
        let mut jumps = 0;

        while pos < self.bytes.len() {
            let len = self.bytes[pos] as usize;
            if len == 0 {
                pos += 1;
                let final_pos = if jumped { jump_pos } else { pos };
                if final_pos + 4 > self.bytes.len() {
                    return None;
                }
                let qtype = u16::from_be_bytes([self.bytes[final_pos], self.bytes[final_pos + 1]]);
                if !name.is_empty() {
                    name.pop();
                } // remove trailing dot
                return Some((name, qtype));
            }

            if (len & 0xC0) == 0xC0 {
                if pos + 2 > self.bytes.len() {
                    return None;
                }
                let offset = ((len & 0x3F) << 8) | (self.bytes[pos + 1] as usize);
                if offset >= self.bytes.len() {
                    return None;
                }
                if !jumped {
                    jump_pos = pos + 2;
                    jumped = true;
                }
                jumps += 1;
                if jumps > 10 {
                    return None;
                } // Prevent infinite loops
                pos = offset;
                continue;
            }

            pos += 1;
            if pos + len > self.bytes.len() {
                return None;
            }
            name.push_str(std::str::from_utf8(&self.bytes[pos..pos + len]).ok()?);
            name.push('.');
            pos += len;
        }
        None
    }

    #[cfg(feature = "ipset")]
    pub fn add_ips(&self, ctx: &mut IpsetAddCtx) {
        self.for_each_ip(|ip| {
            ctx.add(ip);
            false // continue
        });
    }

    /// Internal helper to iterate over IPs in the Answer section without full parsing
    pub fn for_each_ip<F>(&self, mut f: F) -> Option<bool>
    where
        F: FnMut(IpAddr) -> bool,
    {
        let q_end = self.find_question_end()?;
        let mut pos = q_end;
        let answer_count = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);

        for _ in 0..answer_count {
            if pos >= self.bytes.len() {
                break;
            }
            // Skip name (could be compressed)
            pos = self.skip_name(pos)?;
            if pos + 10 > self.bytes.len() {
                break;
            }

            let atype = u16::from_be_bytes([self.bytes[pos], self.bytes[pos + 1]]);
            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlen > self.bytes.len() {
                break;
            }

            if atype == 1 && rdlen == 4 {
                // A
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    self.bytes[pos],
                    self.bytes[pos + 1],
                    self.bytes[pos + 2],
                    self.bytes[pos + 3],
                ));
                if f(ip) {
                    return Some(true);
                }
            } else if atype == 28 && rdlen == 16 {
                // AAAA
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.bytes[pos..pos + 16]);
                let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                if f(ip) {
                    return Some(true);
                }
            }
            pos += rdlen;
        }
        None
    }

    fn skip_name(&self, mut pos: usize) -> Option<usize> {
        while pos < self.bytes.len() {
            let b = self.bytes[pos];
            if b & 0xC0 == 0xC0 {
                return Some(pos + 2); // pointer
            }
            if b == 0 {
                return Some(pos + 1);
            }
            pos += (b as usize) + 1;
        }
        None
    }

    pub fn normalize_ttl(&mut self, min_ttl: u32, max_ttl: u32) {
        let q_end = match self.find_question_end() {
            Some(e) => e,
            None => return,
        };
        let mut pos = q_end;
        let answer_count = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);
        let ns_count = u16::from_be_bytes([self.bytes[8], self.bytes[9]]);

        // Process Answer + Authority sections (skip OPT/type 41)
        for _ in 0..(answer_count + ns_count) {
            pos = match self.skip_name(pos) {
                Some(p) => p,
                None => break,
            };
            if pos + 10 > self.bytes.len() {
                break;
            }

            let rtype = u16::from_be_bytes([self.bytes[pos], self.bytes[pos + 1]]);
            if rtype != 41 {
                // Skip OPT pseudo-records
                let ttl_pos = pos + 4;
                let mut ttl = u32::from_be_bytes([
                    self.bytes[ttl_pos],
                    self.bytes[ttl_pos + 1],
                    self.bytes[ttl_pos + 2],
                    self.bytes[ttl_pos + 3],
                ]);
                if ttl < min_ttl {
                    ttl = min_ttl;
                }
                if ttl > max_ttl {
                    ttl = max_ttl;
                }
                let ttl_bytes = ttl.to_be_bytes();
                self.bytes[ttl_pos..ttl_pos + 4].copy_from_slice(&ttl_bytes);
            }

            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }
    }

    pub fn decrement_ttl(&mut self, subtract_sec: u32) {
        let q_end = match self.find_question_end() {
            Some(e) => e,
            None => return,
        };
        let mut pos = q_end;
        let answer_count = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);
        let ns_count = u16::from_be_bytes([self.bytes[8], self.bytes[9]]);

        // Process Answer + Authority sections (skip OPT/type 41)
        for _ in 0..(answer_count + ns_count) {
            pos = match self.skip_name(pos) {
                Some(p) => p,
                None => break,
            };
            if pos + 10 > self.bytes.len() {
                break;
            }

            let rtype = u16::from_be_bytes([self.bytes[pos], self.bytes[pos + 1]]);
            if rtype != 41 {
                let ttl_pos = pos + 4;
                let mut ttl = u32::from_be_bytes([
                    self.bytes[ttl_pos],
                    self.bytes[ttl_pos + 1],
                    self.bytes[ttl_pos + 2],
                    self.bytes[ttl_pos + 3],
                ]);
                ttl = ttl.saturating_sub(subtract_sec);
                let ttl_bytes = ttl.to_be_bytes();
                self.bytes[ttl_pos..ttl_pos + 4].copy_from_slice(&ttl_bytes);
            }

            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }
    }

    pub fn get_min_ttl(&self) -> u32 {
        let q_end = match self.find_question_end() {
            Some(e) => e,
            None => return 0,
        };
        let mut pos = q_end;
        let answer_count = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);
        let ns_count = u16::from_be_bytes([self.bytes[8], self.bytes[9]]);
        let mut min_ttl = u32::MAX;
        let mut found = false;

        // Process Answer + Authority sections (skip OPT/type 41)
        for _ in 0..(answer_count + ns_count) {
            pos = match self.skip_name(pos) {
                Some(p) => p,
                None => break,
            };
            if pos + 10 > self.bytes.len() {
                break;
            }

            let rtype = u16::from_be_bytes([self.bytes[pos], self.bytes[pos + 1]]);
            if rtype != 41 {
                let ttl_pos = pos + 4;
                let ttl = u32::from_be_bytes([
                    self.bytes[ttl_pos],
                    self.bytes[ttl_pos + 1],
                    self.bytes[ttl_pos + 2],
                    self.bytes[ttl_pos + 3],
                ]);
                if ttl < min_ttl {
                    min_ttl = ttl;
                }
                found = true;
            }

            let rdlen = u16::from_be_bytes([self.bytes[pos + 8], self.bytes[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }
        if found { min_ttl } else { 0 }
    }
}

pub fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(name.len() + 18);
    // Header
    let id = rand::random::<u16>();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // Flags: Standard query
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0

    // Question
    for part in name.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0); // Null byte
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]); // CLASS: IN

    query
}

pub fn build_probe_query() -> Vec<u8> {
    let mut query = Vec::with_capacity(17);
    let id = rand::random::<u16>();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]); // Flags: Standard query, RD=1
    query.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1
    query.extend_from_slice(&[0x00, 0x00]); // ANCOUNT: 0
    query.extend_from_slice(&[0x00, 0x00]); // NSCOUNT: 0
    query.extend_from_slice(&[0x00, 0x00]); // ARCOUNT: 0
    query.push(0); // Root label (.)
    query.extend_from_slice(&[0x00, 0x02]); // QTYPE: NS (2)
    query.extend_from_slice(&[0x00, 0x01]); // CLASS: IN (1)
    query
}

pub fn build_servfail(query: &[u8]) -> Vec<u8> {
    let view = match DnsView::parse(query) {
        Some(m) => m,
        None => return query.to_vec(),
    };
    let q_end = match view.find_question_end() {
        Some(end) => end,
        None => return query.to_vec(),
    };
    let mut msg = query[..q_end].to_vec();
    msg[2] |= 0x80; // Set QR bit (response)
    msg[3] = (msg[3] & 0x70) | 0x82; // Set RA bit, preserve AD/CD/Z, set SERVFAIL rcode (2)
    msg[6..12].fill(0); // Zero out counts
    msg
}

pub fn build_nxdomain(query: &[u8]) -> Vec<u8> {
    let view = match DnsView::parse(query) {
        Some(m) => m,
        None => return query.to_vec(),
    };
    let q_end = match view.find_question_end() {
        Some(end) => end,
        None => return query.to_vec(),
    };
    let mut msg = query[..q_end].to_vec();
    msg[2] |= 0x80; // Set QR bit (response)
    msg[3] = (msg[3] & 0x70) | 0x83; // Set RA bit, preserve AD/CD/Z, set NXDOMAIN rcode (3)
    msg[6..12].fill(0); // Zero out counts
    msg
}

/// Build a DNS response from a query with the given IP addresses as answers.
///
/// **Precondition**: The caller must pre-filter `ips` by query type (A vs AAAA).
/// This function does NOT check whether the IP family matches the QTYPE.
/// In practice, `hosts::get_ips()` handles this filtering before calling here.
pub fn build_hosts_response(query: &[u8], ips: &[std::net::IpAddr]) -> Vec<u8> {
    build_hosts_response_iter(query, ips.iter().copied())
}

pub fn build_hosts_response_iter<I>(query: &[u8], ips: I) -> Vec<u8>
where
    I: IntoIterator<Item = std::net::IpAddr>,
{
    let msg = match DnsView::parse(query) {
        Some(m) => m,
        None => return query.to_vec(),
    };

    let q_end = match msg.find_question_end() {
        Some(end) => end,
        None => return query.to_vec(),
    };

    let mut resp = Vec::with_capacity(q_end + 32);
    resp.extend_from_slice(&query[..q_end]);
    if resp.len() >= 12 {
        resp[2] |= 0x80; // Set QR bit (response)
        resp[3] = (resp[3] & 0x70) | 0x80; // Set RA bit (1), preserve AD/CD/Z, and NOERROR rcode (0)
        resp[6..12].fill(0); // Zero out counts

        let mut count = 0u16;
        for ip in ips {
            // Answer Record: [Name Pointer 0xC00C] [Type] [Class 0x0001] [TTL] [RDLEN] [RDATA]
            resp.push(0xC0);
            resp.push(0x0C);
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    resp.extend_from_slice(&[0x00, 0x01]); // Type A
                    resp.extend_from_slice(&[0x00, 0x01]); // Class IN
                    resp.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL 3600
                    resp.extend_from_slice(&[0x00, 0x04]); // RDLEN 4
                    resp.extend_from_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    resp.extend_from_slice(&[0x00, 0x1C]); // Type AAAA
                    resp.extend_from_slice(&[0x00, 0x01]); // Class IN
                    resp.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL 3600
                    resp.extend_from_slice(&[0x00, 0x10]); // RDLEN 16
                    resp.extend_from_slice(&ipv6.octets());
                }
            }
            count = count.saturating_add(1);
        }
        let count_bytes = count.to_be_bytes();
        resp[6] = count_bytes[0];
        resp[7] = count_bytes[1]; // ANCOUNT
    }
    resp
}

pub fn qtype_to_str(qtype: u16) -> std::borrow::Cow<'static, str> {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{}", other).into(),
    }
}

/// Skip a DNS name in a raw byte buffer, handling both labels and compression pointers.
/// Returns the position after the name.
fn skip_name_raw(bytes: &[u8], mut pos: usize) -> Option<usize> {
    while pos < bytes.len() {
        let b = bytes[pos];
        if b & 0xC0 == 0xC0 {
            return Some(pos + 2); // compression pointer
        }
        if b == 0 {
            return Some(pos + 1); // end of name
        }
        pos += (b as usize) + 1;
    }
    None
}

/// Skip the question section in a raw DNS message buffer.
/// Handles QNAME compression pointers (unlike the old label-length-only walk).
/// Returns the position after QNAME + QTYPE(2) + QCLASS(2).
fn skip_qsection_raw(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 12 {
        return None;
    }
    let qd_count = u16::from_be_bytes([bytes[4], bytes[5]]);
    if qd_count == 0 {
        return Some(12);
    }
    let mut pos = 12;
    for _ in 0..qd_count {
        let name_end = skip_name_raw(bytes, pos)?;
        pos = name_end + 4;
        if pos > bytes.len() {
            return None;
        }
    }
    Some(pos)
}

/// Decrement TTLs in-place on a raw DNS response buffer.
/// Processes Answer + Authority sections, skipping OPT (type 41) records.
/// This avoids allocating a DnsMessage just to modify TTLs.
pub fn decrement_ttl_in_place(bytes: &mut [u8], subtract_sec: u32) {
    if bytes.len() < 12 {
        return;
    }

    let mut pos = match skip_qsection_raw(bytes) {
        Some(p) => p,
        None => return,
    };

    let answer_count = u16::from_be_bytes([bytes[6], bytes[7]]);
    let ns_count = u16::from_be_bytes([bytes[8], bytes[9]]);

    for _ in 0..(answer_count + ns_count) {
        pos = match skip_name_raw(bytes, pos) {
            Some(p) => p,
            None => return,
        };
        if pos + 10 > bytes.len() {
            break;
        }

        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        if rtype != 41 {
            // Skip OPT pseudo-records
            let ttl_pos = pos + 4;
            let mut ttl = u32::from_be_bytes([
                bytes[ttl_pos],
                bytes[ttl_pos + 1],
                bytes[ttl_pos + 2],
                bytes[ttl_pos + 3],
            ]);
            ttl = ttl.saturating_sub(subtract_sec);
            bytes[ttl_pos..ttl_pos + 4].copy_from_slice(&ttl.to_be_bytes());
        }

        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10 + rdlen;
    }
}

/// Normalize Answer + Authority TTLs in-place, skipping OPT (type 41) records.
pub fn normalize_ttl_in_place(bytes: &mut [u8], min_ttl: u32, max_ttl: u32) {
    if bytes.len() < 12 {
        return;
    }

    let mut pos = match skip_qsection_raw(bytes) {
        Some(p) => p,
        None => return,
    };

    let answer_count = u16::from_be_bytes([bytes[6], bytes[7]]);
    let ns_count = u16::from_be_bytes([bytes[8], bytes[9]]);

    for _ in 0..(answer_count + ns_count) {
        pos = match skip_name_raw(bytes, pos) {
            Some(p) => p,
            None => return,
        };
        if pos + 10 > bytes.len() {
            break;
        }

        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        if rtype != 41 {
            let ttl_pos = pos + 4;
            let mut ttl = u32::from_be_bytes([
                bytes[ttl_pos],
                bytes[ttl_pos + 1],
                bytes[ttl_pos + 2],
                bytes[ttl_pos + 3],
            ]);
            if ttl < min_ttl {
                ttl = min_ttl;
            }
            if ttl > max_ttl {
                ttl = max_ttl;
            }
            bytes[ttl_pos..ttl_pos + 4].copy_from_slice(&ttl.to_be_bytes());
        }

        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10 + rdlen;
    }
}

/// Force all Answer + Authority TTLs in the buffer to 1.
/// Skips OPT (type 41) records.
pub fn set_ttl_to_one(bytes: &mut [u8]) {
    if bytes.len() < 12 {
        return;
    }

    let mut pos = match skip_qsection_raw(bytes) {
        Some(p) => p,
        None => return,
    };

    let answer_count = u16::from_be_bytes([bytes[6], bytes[7]]);
    let ns_count = u16::from_be_bytes([bytes[8], bytes[9]]);

    for _ in 0..(answer_count + ns_count) {
        pos = match skip_name_raw(bytes, pos) {
            Some(p) => p,
            None => return,
        };
        if pos + 10 > bytes.len() {
            break;
        }

        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        if rtype != 41 {
            let ttl_pos = pos + 4;
            bytes[ttl_pos..ttl_pos + 4].copy_from_slice(&[0, 0, 0, 1]);
        }

        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10 + rdlen;
    }
}

/// Overwrite the first 2 bytes (Transaction ID) of a DNS message buffer.
pub fn set_id_in_place(bytes: &mut [u8], id: [u8; 2]) {
    if bytes.len() >= 2 {
        bytes[0] = id[0];
        bytes[1] = id[1];
    }
}

pub fn build_empty_reply(query: &[u8]) -> Vec<u8> {
    let view = match DnsView::parse(query) {
        Some(m) => m,
        None => return query.to_vec(),
    };
    let q_end = match view.find_question_end() {
        Some(end) => end,
        None => return query.to_vec(),
    };
    let mut msg = query[..q_end].to_vec();
    if msg.len() >= 4 {
        msg[2] |= 0x80; // Set QR bit
        msg[3] = (msg[3] & 0x70) | 0x80; // Clear RCODE, set RA, preserve AD/CD/Z
    }
    if msg.len() >= 12 {
        msg[6..12].fill(0); // Zero out counts
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_question_end_compressed() {
        let msg = DnsMessage::parse(&[
            0, 1, // ID
            0, 0, // Flags
            0, 1, // QDCOUNT = 1
            0, 0, // ANCOUNT
            0, 0, // NSCOUNT
            0, 0, // ARCOUNT
            3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm',
            0, // QNAME
            0, 1, // QTYPE = A (1)
            0, 1, // QCLASS = IN (1)
        ])
        .unwrap();
        assert_eq!(msg.find_question_end(), Some(32));
        assert_eq!(
            msg.get_qname_and_type(),
            Some((compact_str::CompactString::new("www.google.com"), 1))
        );

        let msg2 = DnsMessage::parse(&[
            0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0xC0,
            24, // QNAME: www. -> offset 24
            0, 1, 0, 1, // QTYPE: A, QCLASS: IN
            0, 0, // padding
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // google.com
        ])
        .unwrap();
        assert_eq!(msg2.find_question_end(), Some(22));
        assert_eq!(
            msg2.get_qname_and_type(),
            Some((compact_str::CompactString::new("www.google.com"), 1))
        );
    }

    #[test]
    fn test_cacheable_and_upstream_acceptable_semantics() {
        let mut resp = build_query("example.com", 1);
        resp[2] |= 0x80; // QR

        let msg = DnsMessage::parse(&resp).unwrap();
        assert!(msg.is_cacheable());
        assert!(msg.is_acceptable_upstream_response());

        let mut truncated = resp.clone();
        truncated[2] |= 0x02; // TC
        let msg = DnsMessage::parse(&truncated).unwrap();
        assert!(!msg.is_cacheable());
        assert!(msg.is_acceptable_upstream_response());

        let mut servfail = resp;
        servfail[3] = (servfail[3] & 0xF0) | 0x02; // SERVFAIL
        let msg = DnsMessage::parse(&servfail).unwrap();
        assert!(!msg.is_cacheable());
        assert!(!msg.is_acceptable_upstream_response());
    }

    #[test]
    fn test_zero_qdcount_and_flag_preservation() {
        let mut query = build_query("example.com", 1);
        query[3] |= 0x30; // Set AD (bit 5) and CD (bit 4)

        let sf = build_servfail(&query);
        assert_eq!(sf[3] & 0x30, 0x30);
        assert_eq!(sf[3] & 0x0F, 2);

        let nx = build_nxdomain(&query);
        assert_eq!(nx[3] & 0x30, 0x30);
        assert_eq!(nx[3] & 0x0F, 3);

        let hosts_resp = build_hosts_response(&query, &[std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))]);
        assert_eq!(hosts_resp[3] & 0x30, 0x30);
        assert_eq!(hosts_resp[3] & 0x0F, 0);

        // Test zero qd_count
        let mut zero_qd = query;
        zero_qd[4] = 0;
        zero_qd[5] = 0;
        let view = DnsView::parse(&zero_qd).unwrap();
        assert_eq!(view.find_question_end(), Some(12));
        assert_eq!(view.get_qname_and_type(), None);
        assert_eq!(skip_qsection_raw(&zero_qd), Some(12));
    }
}
