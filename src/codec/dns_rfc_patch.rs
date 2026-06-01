use crate::codec::dns::{encode_name, parse_header, parse_name, skip_name, skip_rr};

type AnswerRecordMeta = (usize, usize, String, u16, u16, u32, usize, usize);

/// RFC-compliant answer section normalization for CNAME链终止
/// 保证：
/// 1. 若有CNAME链，answer section 只保留CNAME链和最后一跳的目标类型记录（如A/AAAA），移除同名A记录
/// 2. CNAME记录在answer section最前，后面紧跟CNAME target的A/AAAA
pub fn normalize_cname_chain_answers(packet: &[u8], qtype: u16) -> Option<Vec<u8>> {
    fn push_rr(
        out: &mut Vec<u8>,
        owner: &str,
        rr_type: u16,
        rr_class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> Option<()> {
        encode_name(owner, out)?;
        out.extend_from_slice(&rr_type.to_be_bytes());
        out.extend_from_slice(&rr_class.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        Some(())
    }

    let header = parse_header(packet).ok()?;
    let mut offset = 12usize;
    for _ in 0..header.qdcount {
        offset = skip_name(packet, offset)?;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4;
    }
    let answer_start = offset;
    let mut rr_offsets: Vec<AnswerRecordMeta> = Vec::new();
    let mut cname_chain: Vec<(String, String, u32)> = Vec::new();
    let mut dname_records: Vec<(String, u16, u16, u32, Vec<u8>)> = Vec::new();
    let mut final_target: Option<String> = None;
    let mut seen_cname = false;
    let mut i = 0;
    let mut cur_offset = offset;
    while i < header.ancount {
        let rr_start = cur_offset;
        let (owner, consumed) = parse_name(packet, cur_offset)?;
        cur_offset += consumed;
        if cur_offset + 10 > packet.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([packet[cur_offset], packet[cur_offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[cur_offset + 2], packet[cur_offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[cur_offset + 4],
            packet[cur_offset + 5],
            packet[cur_offset + 6],
            packet[cur_offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[cur_offset + 8], packet[cur_offset + 9]]) as usize;
        let rdata_offset = cur_offset + 10;
        if rdata_offset + rdlen > packet.len() {
            return None;
        }
        if rr_type == 5 && rr_class == 1 {
            // CNAME
            let (target, _) = parse_name(packet, rdata_offset)?;
            cname_chain.push((owner.clone(), target.clone(), ttl));
            final_target = Some(target);
            seen_cname = true;
        } else if rr_type == 39 && rr_class == 1 {
            dname_records.push((
                owner.clone(),
                rr_type,
                rr_class,
                ttl,
                packet[rdata_offset..rdata_offset + rdlen].to_vec(),
            ));
        }
        rr_offsets.push((
            rr_start,
            cur_offset + 10 + rdlen,
            owner.clone(),
            rr_type,
            rr_class,
            ttl,
            rdata_offset,
            rdlen,
        ));
        cur_offset = rdata_offset + rdlen;
        i += 1;
    }
    // 若无CNAME链，直接返回原包
    if !seen_cname {
        return Some(packet.to_vec());
    }
    // 构造新answer section
    let mut new_answers = Vec::new();
    // 1. 先保留 DNAME，避免 synthesized CNAME 规范化时把 DNAME 丢掉。
    for (owner, rr_type, rr_class, ttl, rdata) in &dname_records {
        push_rr(&mut new_answers, owner, *rr_type, *rr_class, *ttl, rdata)?;
    }
    // 2. 追加CNAME链
    for (owner, target, ttl) in &cname_chain {
        let mut rr = Vec::new();
        encode_name(owner, &mut rr)?;
        rr.extend_from_slice(&5u16.to_be_bytes());
        rr.extend_from_slice(&1u16.to_be_bytes());
        rr.extend_from_slice(&ttl.to_be_bytes());
        let mut rdata = Vec::new();
        encode_name(target, &mut rdata)?;
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(&rdata);
        new_answers.extend_from_slice(&rr);
    }
    // 3. 追加CNAME target的目标类型记录（如A/AAAA）
    let mut added_rr_count: u16 = 0;
    if let Some(target) = final_target {
        for (_, _, owner, rr_type, rr_class, ttl, rdata_offset, rdlen) in &rr_offsets {
            if owner
                .trim_end_matches('.')
                .eq_ignore_ascii_case(target.trim_end_matches('.'))
                && *rr_type == qtype
                && *rr_class == 1
            {
                push_rr(
                    &mut new_answers,
                    owner,
                    *rr_type,
                    *rr_class,
                    *ttl,
                    &packet[*rdata_offset..(*rdata_offset + *rdlen)],
                )?;
                added_rr_count = added_rr_count.saturating_add(1);
            }
        }

        // Some recursive servers may carry terminal A/AAAA in Additional.
        // Promote them into Answer to keep client behavior stable.
        if added_rr_count == 0 {
            let mut rest_offset = answer_start;
            for _ in 0..header.ancount {
                rest_offset = skip_rr(packet, rest_offset)?;
            }
            for _ in 0..header.nscount {
                rest_offset = skip_rr(packet, rest_offset)?;
            }

            let mut ar_offset = rest_offset;
            for _ in 0..header.arcount {
                let (owner, consumed) = parse_name(packet, ar_offset)?;
                ar_offset += consumed;
                if ar_offset + 10 > packet.len() {
                    return None;
                }

                let rr_type = u16::from_be_bytes([packet[ar_offset], packet[ar_offset + 1]]);
                let rr_class = u16::from_be_bytes([packet[ar_offset + 2], packet[ar_offset + 3]]);
                let rdlen =
                    u16::from_be_bytes([packet[ar_offset + 8], packet[ar_offset + 9]]) as usize;
                let rr_end = ar_offset + 10 + rdlen;
                if rr_end > packet.len() {
                    return None;
                }

                if owner
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(target.trim_end_matches('.'))
                    && rr_type == qtype
                    && rr_class == 1
                {
                    let ttl = u32::from_be_bytes([
                        packet[ar_offset + 4],
                        packet[ar_offset + 5],
                        packet[ar_offset + 6],
                        packet[ar_offset + 7],
                    ]);
                    let rdata_offset = ar_offset + 10;
                    push_rr(
                        &mut new_answers,
                        &owner,
                        rr_type,
                        rr_class,
                        ttl,
                        &packet[rdata_offset..rr_end],
                    )?;
                    added_rr_count = added_rr_count.saturating_add(1);
                }

                ar_offset = rr_end;
            }
        }
    }
    if added_rr_count == 0 {
        return Some(packet.to_vec());
    }
    // 3. answer count
    let new_ancount = (dname_records.len() + cname_chain.len()) as u16 + added_rr_count;
    // 4. 拼接新包
    let mut out = Vec::with_capacity(packet.len());
    out.extend_from_slice(&packet[..answer_start]);
    out.extend_from_slice(&new_answers);
    // authority/additional section
    let orig_header = parse_header(packet).ok()?;
    let mut rest_offset = answer_start;
    for _ in 0..orig_header.ancount {
        rest_offset = skip_rr(packet, rest_offset)?;
    }
    out.extend_from_slice(&packet[rest_offset..]);
    // 修正ancount
    out[6..8].copy_from_slice(&new_ancount.to_be_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::normalize_cname_chain_answers;

    fn basic_request(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&0x1234u16.to_be_bytes());
        packet.extend_from_slice(&0x0100u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        for label in name.trim_end_matches('.').split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn normalize_cname_chain_answers_preserves_multiple_terminal_a_records() {
        let target_request = basic_request("www.abc.com", 1);

        let terminal = crate::codec::dns::build_authoritative_answer_multi(
            &target_request,
            &[
                "3.175.207.59".to_string(),
                "3.175.207.120".to_string(),
                "3.175.207.51".to_string(),
                "3.175.207.14".to_string(),
            ],
            60,
            "A",
        )
        .expect("terminal packet");

        let merged = crate::codec::dns::append_cname_answers(
            &terminal,
            &[("abc.test.com".to_string(), "www.abc.com".to_string(), 300)],
        )
        .expect("merged packet");

        let normalized = normalize_cname_chain_answers(&merged, 1).expect("normalized packet");
        let a_records = crate::codec::dns::extract_answer_records_by_type(&normalized, 1);
        let cname_records = crate::codec::dns::extract_answer_cname_records(&normalized);

        assert_eq!(cname_records.len(), 1);
        assert_eq!(a_records.len(), 4);

        let answers: std::collections::HashSet<_> = a_records
            .into_iter()
            .filter_map(|(_, _, _, _, rdata)| {
                if rdata.len() == 4 {
                    Some(format!(
                        "{}.{}.{}.{}",
                        rdata[0], rdata[1], rdata[2], rdata[3]
                    ))
                } else {
                    None
                }
            })
            .collect();

        assert!(answers.contains("3.175.207.59"));
        assert!(answers.contains("3.175.207.120"));
        assert!(answers.contains("3.175.207.51"));
        assert!(answers.contains("3.175.207.14"));
    }
}
