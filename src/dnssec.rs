use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use data_encoding::{BASE32_DNSSEC, BASE64};
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, DS, NSEC, NSEC3, RRSIG};
use hickory_proto::dnssec::{Algorithm, Nsec3HashAlgorithm, PublicKeyBuf, TrustAnchors, Verifier};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ValidationState {
    Secure,
    Insecure,
}

#[derive(Debug, Clone)]
pub struct ValidatedKeys {
    pub zone: Name,
    pub keys: Vec<Record>,
}

pub fn parse_message(packet: &[u8]) -> Result<Message> {
    Message::from_vec(packet).map_err(|err| anyhow!(err.to_string()))
}

pub fn validation_requested(request: &[u8]) -> bool {
    crate::codec::dns::dnssec_ok_requested(request)
        && !crate::codec::dns::checking_disabled(request)
}

pub fn root_trust_anchors() -> TrustAnchors {
    TrustAnchors::default()
}

pub fn load_trust_anchors(
    config_path: &str,
    use_builtin_trust_anchors: bool,
    trust_anchor_files: &[String],
) -> Result<TrustAnchors> {
    let mut trust_anchors = if use_builtin_trust_anchors {
        TrustAnchors::default()
    } else {
        TrustAnchors::empty()
    };

    for path in trust_anchor_files {
        let resolved_path = resolve_trust_anchor_path(config_path, path);
        let loaded = parse_trust_anchor_file(&resolved_path)?;
        for index in 0..loaded.len() {
            let Some(anchor) = loaded.get(index) else {
                continue;
            };
            trust_anchors.insert(anchor);
        }
    }

    Ok(trust_anchors)
}

fn resolve_trust_anchor_path(config_path: &str, path: &str) -> PathBuf {
    let trust_anchor_path = Path::new(path);
    if trust_anchor_path.is_absolute() {
        return trust_anchor_path.to_path_buf();
    }

    let Some(config_dir) = Path::new(config_path).parent() else {
        return trust_anchor_path.to_path_buf();
    };

    config_dir.join(trust_anchor_path)
}

fn parse_trust_anchor_file(path: &Path) -> Result<TrustAnchors> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read trust anchor file: {}", path.display()))?;
    let mut trust_anchors = TrustAnchors::empty();

    for entry in logical_zone_lines(&raw) {
        let tokens = entry.split_whitespace().collect::<Vec<_>>();
        let Some(dnskey_index) = tokens
            .iter()
            .position(|token| token.eq_ignore_ascii_case("DNSKEY"))
        else {
            continue;
        };
        if tokens.len() < dnskey_index + 5 {
            return Err(anyhow!(
                "invalid DNSKEY trust anchor line in {}: {entry}",
                path.display()
            ));
        }

        let flags = tokens[dnskey_index + 1]
            .parse::<u16>()
            .with_context(|| format!("invalid DNSKEY flags in {}: {entry}", path.display()))?;
        let _protocol = tokens[dnskey_index + 2]
            .parse::<u8>()
            .with_context(|| format!("invalid DNSKEY protocol in {}: {entry}", path.display()))?;
        let algorithm = parse_dnskey_algorithm(tokens[dnskey_index + 3])
            .with_context(|| format!("invalid DNSKEY algorithm in {}: {entry}", path.display()))?;
        let public_key = BASE64
            .decode(tokens[dnskey_index + 4..].join("").as_bytes())
            .map_err(|err| anyhow!("invalid DNSKEY public key in {}: {err}", path.display()))?;

        let dnskey = DNSKEY::with_flags(flags, PublicKeyBuf::new(public_key, algorithm));
        let key = dnskey
            .key()
            .with_context(|| format!("unsupported DNSKEY public key in {}", path.display()))?;
        trust_anchors.insert(key.as_ref());
    }

    Ok(trust_anchors)
}

fn logical_zone_lines(raw: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut paren_depth = 0usize;

    for line in raw.lines() {
        let content = line.split(';').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }

        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(content);
        paren_depth += content.matches('(').count();
        paren_depth = paren_depth.saturating_sub(content.matches(')').count());

        if paren_depth == 0 {
            entries.push(current.replace(['(', ')'], " "));
            current.clear();
        }
    }

    if !current.trim().is_empty() {
        entries.push(current.replace(['(', ')'], " "));
    }

    entries
}

#[allow(deprecated)]
fn parse_dnskey_algorithm(value: &str) -> Result<Algorithm> {
    let normalized = value.trim().to_ascii_uppercase();
    let algorithm = match normalized.as_str() {
        "RSAMD5" => Algorithm::RSAMD5,
        "DSA" => Algorithm::DSA,
        "RSASHA1" => Algorithm::RSASHA1,
        "RSASHA1-NSEC3-SHA1" => Algorithm::RSASHA1NSEC3SHA1,
        "RSASHA256" => Algorithm::RSASHA256,
        "RSASHA512" => Algorithm::RSASHA512,
        "ECDSAP256SHA256" => Algorithm::ECDSAP256SHA256,
        "ECDSAP384SHA384" => Algorithm::ECDSAP384SHA384,
        "ED25519" => Algorithm::ED25519,
        _ => Algorithm::from_u8(normalized.parse::<u8>()?),
    };

    Ok(algorithm)
}

pub fn response_has_dnssec_records(packet: &[u8]) -> bool {
    let Ok(message) = parse_message(packet) else {
        return false;
    };

    let has_dnssec = all_records(&message).any(|record| {
        matches!(
            record.record_type(),
            RecordType::RRSIG | RecordType::DNSKEY | RecordType::DS
        )
    });
    has_dnssec
}

pub fn collect_signed_rrsets(message: &Message) -> Vec<(Name, RecordType)> {
    let mut rrsets = BTreeSet::new();
    for record in message.answers() {
        if matches!(record.record_type(), RecordType::RRSIG) {
            continue;
        }
        rrsets.insert((record.name().clone(), record.record_type()));
    }
    rrsets.into_iter().collect()
}

pub fn verify_message_rrsets(
    message: &Message,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<ValidationState> {
    let rrsets = collect_signed_rrsets(message);
    let mut saw_dnssec_material = false;
    for (name, record_type) in rrsets {
        let records = collect_rrset_records(message, &name, record_type);
        let rrsigs = collect_rrsig_records(message, &name, record_type);
        if rrsigs.is_empty() {
            continue;
        }
        saw_dnssec_material = true;
        verify_rrset(&name, &records, &rrsigs, &trusted_zone_keys.keys)?;
    }

    if saw_dnssec_material {
        Ok(ValidationState::Secure)
    } else {
        match validate_negative_response(message, trusted_zone_keys)? {
            Some(state) => Ok(state),
            None if response_contains_dnssec_material(message) => {
                bail!("dnssec material present but response proof could not be validated")
            }
            None => Ok(ValidationState::Insecure),
        }
    }
}

fn validate_negative_response(
    message: &Message,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<Option<ValidationState>> {
    let Some(query) = message.query() else {
        return Ok(None);
    };

    if !message.answers().is_empty() {
        return Ok(None);
    }

    match message.response_code() {
        ResponseCode::NoError => {
            if is_referral_response(message) {
                if let Some(state) = validate_referral_nsec(message, trusted_zone_keys)? {
                    return Ok(Some(state));
                }
                if let Some(state) = validate_referral_nsec3(message, trusted_zone_keys)? {
                    return Ok(Some(state));
                }
            }

            if let Some(state) =
                validate_nodata_nsec(message, query.name(), query.query_type(), trusted_zone_keys)?
            {
                return Ok(Some(state));
            }
            if let Some(state) =
                validate_nodata_nsec3(message, query.name(), query.query_type(), trusted_zone_keys)?
            {
                return Ok(Some(state));
            }
            Ok(None)
        }
        ResponseCode::NXDomain => {
            if validate_nxdomain_nsec(message, query.name(), trusted_zone_keys)? {
                return Ok(Some(ValidationState::Secure));
            }
            if validate_nxdomain_nsec3(message, query.name(), trusted_zone_keys)? {
                return Ok(Some(ValidationState::Secure));
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn validate_nodata_nsec(
    message: &Message,
    qname: &Name,
    qtype: RecordType,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<Option<ValidationState>> {
    let verified_nsecs = verified_nsec_records(message, trusted_zone_keys)?;

    for (record, nsec) in &verified_nsecs {
        if record.name() != qname {
            continue;
        }
        if !type_present_in_bitmap(nsec.type_bit_maps(), qtype)
            && !type_present_in_bitmap(nsec.type_bit_maps(), RecordType::CNAME)
        {
            return Ok(Some(ValidationState::Secure));
        }
    }

    for (record, nsec) in verified_nsecs {
        let Some(closest_encloser) = wildcard_closest_encloser(record.name()) else {
            continue;
        };
        if !type_present_in_bitmap(nsec.type_bit_maps(), qtype)
            && !type_present_in_bitmap(nsec.type_bit_maps(), RecordType::CNAME)
            && verified_nsec_records_cover_name(
                message,
                trusted_zone_keys,
                &next_closer_name(qname, &closest_encloser),
            )?
        {
            return Ok(Some(ValidationState::Secure));
        }
    }

    Ok(None)
}

fn validate_nxdomain_nsec(
    message: &Message,
    qname: &Name,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<bool> {
    let verified_nsecs = verified_nsec_records(message, trusted_zone_keys)?;
    if verified_nsecs.is_empty() {
        return Ok(false);
    }

    let covers_qname = verified_nsecs
        .iter()
        .any(|(record, nsec)| nsec_covers_name(record.name(), nsec.next_domain_name(), qname));
    if !covers_qname {
        return Ok(false);
    }

    let Some(closest_encloser) = find_closest_encloser(qname, |candidate| {
        verified_nsecs
            .iter()
            .any(|(record, _)| record.name() == candidate)
    }) else {
        return Ok(false);
    };

    let wildcard = wildcard_name(&closest_encloser)?;
    Ok(verified_nsecs
        .iter()
        .any(|(record, nsec)| nsec_covers_name(record.name(), nsec.next_domain_name(), &wildcard)))
}

fn validate_nodata_nsec3(
    message: &Message,
    qname: &Name,
    qtype: RecordType,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<Option<ValidationState>> {
    let verified_nsec3s = verified_nsec3_records(message, trusted_zone_keys)?;
    let Some((hash_algorithm, salt, iterations)) = nsec3_params(&verified_nsec3s) else {
        return Ok(None);
    };

    let qname_hash = hash_nsec3_name(qname, hash_algorithm, salt, iterations)?;
    for (_, nsec3, owner_hash) in &verified_nsec3s {
        if *owner_hash != qname_hash {
            continue;
        }
        if !type_present_in_bitmap(nsec3.type_bit_maps(), qtype)
            && !type_present_in_bitmap(nsec3.type_bit_maps(), RecordType::CNAME)
        {
            return Ok(Some(ValidationState::Secure));
        }
    }

    let Some(proof) = find_nsec3_closest_encloser_proof(qname, &verified_nsec3s)? else {
        return Ok(None);
    };

    if qtype == RecordType::DS && proof.covering_opt_out {
        return Ok(Some(ValidationState::Insecure));
    }

    let wildcard = wildcard_name(&proof.closest_encloser)?;
    let wildcard_hash = hash_nsec3_name(&wildcard, hash_algorithm, salt, iterations)?;
    for (_, nsec3, owner_hash) in &verified_nsec3s {
        if *owner_hash != wildcard_hash {
            continue;
        }
        if !type_present_in_bitmap(nsec3.type_bit_maps(), qtype)
            && !type_present_in_bitmap(nsec3.type_bit_maps(), RecordType::CNAME)
        {
            return Ok(Some(ValidationState::Secure));
        }
    }

    Ok(None)
}

fn validate_nxdomain_nsec3(
    message: &Message,
    qname: &Name,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<bool> {
    let verified_nsec3s = verified_nsec3_records(message, trusted_zone_keys)?;
    if verified_nsec3s.is_empty() {
        return Ok(false);
    }

    let Some((hash_algorithm, salt, iterations)) = nsec3_params(&verified_nsec3s) else {
        return Ok(false);
    };

    let Some(proof) = find_nsec3_closest_encloser_proof(qname, &verified_nsec3s)? else {
        return Ok(false);
    };

    let wildcard = wildcard_name(&proof.closest_encloser)?;
    let wildcard_hash = hash_nsec3_name(&wildcard, hash_algorithm, salt, iterations)?;
    Ok(verified_nsec3s.iter().any(|(_, nsec3, owner_hash)| {
        nsec3_covers_hash(owner_hash, nsec3.next_hashed_owner_name(), &wildcard_hash)
    }))
}

fn validate_referral_nsec(
    message: &Message,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<Option<ValidationState>> {
    let Some(delegation_name) = authority_delegation_name(message) else {
        return Ok(None);
    };

    let verified_nsecs = verified_nsec_records(message, trusted_zone_keys)?;
    for (record, nsec) in verified_nsecs {
        if record.name() != &delegation_name {
            continue;
        }
        if type_present_in_bitmap(nsec.type_bit_maps(), RecordType::NS)
            && !type_present_in_bitmap(nsec.type_bit_maps(), RecordType::DS)
            && !type_present_in_bitmap(nsec.type_bit_maps(), RecordType::SOA)
        {
            return Ok(Some(ValidationState::Insecure));
        }
    }

    Ok(None)
}

fn validate_referral_nsec3(
    message: &Message,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<Option<ValidationState>> {
    let Some(delegation_name) = authority_delegation_name(message) else {
        return Ok(None);
    };

    let verified_nsec3s = verified_nsec3_records(message, trusted_zone_keys)?;
    let Some((hash_algorithm, salt, iterations)) = nsec3_params(&verified_nsec3s) else {
        return Ok(None);
    };

    let delegation_hash = hash_nsec3_name(&delegation_name, hash_algorithm, salt, iterations)?;
    for (_, nsec3, owner_hash) in &verified_nsec3s {
        if *owner_hash != delegation_hash {
            continue;
        }
        if type_present_in_bitmap(nsec3.type_bit_maps(), RecordType::NS)
            && !type_present_in_bitmap(nsec3.type_bit_maps(), RecordType::DS)
            && !type_present_in_bitmap(nsec3.type_bit_maps(), RecordType::SOA)
        {
            return Ok(Some(ValidationState::Insecure));
        }
    }

    let Some(proof) = find_nsec3_closest_encloser_proof(&delegation_name, &verified_nsec3s)? else {
        return Ok(None);
    };

    if proof.covering_opt_out {
        return Ok(Some(ValidationState::Insecure));
    }

    Ok(None)
}

fn verified_nsec_records<'a>(
    message: &'a Message,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<Vec<(&'a Record, &'a NSEC)>> {
    let mut verified = Vec::new();
    for record in message.name_servers() {
        let Some(nsec) = as_nsec(record) else {
            continue;
        };
        if verify_negative_rrset(
            message,
            record.name(),
            RecordType::NSEC,
            &trusted_zone_keys.keys,
        )? {
            verified.push((record, nsec));
        }
    }
    Ok(verified)
}

fn verified_nsec3_records<'a>(
    message: &'a Message,
    trusted_zone_keys: &ValidatedKeys,
) -> Result<Vec<(&'a Record, &'a NSEC3, Vec<u8>)>> {
    let mut verified = Vec::new();
    for record in message.name_servers() {
        let Some(nsec3) = as_nsec3(record) else {
            continue;
        };
        if !verify_negative_rrset(
            message,
            record.name(),
            RecordType::NSEC3,
            &trusted_zone_keys.keys,
        )? {
            continue;
        }
        let owner_hash = nsec3_owner_hash(record.name())?;
        verified.push((record, nsec3, owner_hash));
    }
    Ok(verified)
}

fn verify_negative_rrset(
    message: &Message,
    name: &Name,
    record_type: RecordType,
    candidate_keys: &[Record],
) -> Result<bool> {
    let records = collect_rrset_records(message, name, record_type);
    let rrsigs = collect_rrsig_records(message, name, record_type);
    if records.is_empty() || rrsigs.is_empty() {
        return Ok(false);
    }

    verify_rrset(name, &records, &rrsigs, candidate_keys)?;
    Ok(true)
}

fn response_contains_dnssec_material(message: &Message) -> bool {
    all_records(message).any(|record| {
        matches!(
            record.record_type(),
            RecordType::RRSIG
                | RecordType::DNSKEY
                | RecordType::DS
                | RecordType::NSEC
                | RecordType::NSEC3
        )
    })
}

fn is_referral_response(message: &Message) -> bool {
    !message
        .name_servers()
        .iter()
        .any(|record| record.record_type() == RecordType::SOA)
        && authority_delegation_name(message).is_some()
}

fn authority_delegation_name(message: &Message) -> Option<Name> {
    message
        .name_servers()
        .iter()
        .find(|record| record.record_type() == RecordType::NS)
        .map(|record| record.name().clone())
}

fn wildcard_closest_encloser(name: &Name) -> Option<Name> {
    let mut labels = name.iter();
    let first = labels.next()?;
    if first != b"*" {
        return None;
    }
    Name::from_labels(labels.collect::<Vec<_>>()).ok()
}

fn verified_nsec_records_cover_name(
    message: &Message,
    trusted_zone_keys: &ValidatedKeys,
    target: &Name,
) -> Result<bool> {
    Ok(verified_nsec_records(message, trusted_zone_keys)?
        .iter()
        .any(|(record, nsec)| nsec_covers_name(record.name(), nsec.next_domain_name(), target)))
}

fn nsec3_params<'a>(
    verified_nsec3s: &'a [(&'a Record, &'a NSEC3, Vec<u8>)],
) -> Option<(Nsec3HashAlgorithm, &'a [u8], u16)> {
    verified_nsec3s
        .first()
        .map(|(_, nsec3, _)| (nsec3.hash_algorithm(), nsec3.salt(), nsec3.iterations()))
}

struct Nsec3ClosestEncloserProof {
    closest_encloser: Name,
    covering_opt_out: bool,
}

fn find_nsec3_closest_encloser_proof(
    qname: &Name,
    verified_nsec3s: &[(&Record, &NSEC3, Vec<u8>)],
) -> Result<Option<Nsec3ClosestEncloserProof>> {
    let Some((hash_algorithm, salt, iterations)) = nsec3_params(verified_nsec3s) else {
        return Ok(None);
    };

    let label_count = qname.num_labels() as usize;
    for labels in (0..=label_count).rev() {
        let candidate = qname.trim_to(labels);
        let candidate_hash = hash_nsec3_name(&candidate, hash_algorithm, salt, iterations)?;
        if !verified_nsec3s
            .iter()
            .any(|(_, _, owner_hash)| *owner_hash == candidate_hash)
        {
            continue;
        }

        let next_closer = next_closer_name(qname, &candidate);
        if next_closer == candidate {
            continue;
        }

        let next_closer_hash = hash_nsec3_name(&next_closer, hash_algorithm, salt, iterations)?;
        let Some((_, covering_nsec3, _)) = verified_nsec3s.iter().find(|(_, nsec3, owner_hash)| {
            nsec3_covers_hash(
                owner_hash,
                nsec3.next_hashed_owner_name(),
                &next_closer_hash,
            )
        }) else {
            continue;
        };

        return Ok(Some(Nsec3ClosestEncloserProof {
            closest_encloser: candidate,
            covering_opt_out: covering_nsec3.opt_out(),
        }));
    }

    Ok(None)
}

fn find_closest_encloser<F>(qname: &Name, mut exists: F) -> Option<Name>
where
    F: FnMut(&Name) -> bool,
{
    let label_count = qname.num_labels() as usize;
    for labels in (0..=label_count).rev() {
        let candidate = qname.trim_to(labels);
        if exists(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn next_closer_name(qname: &Name, closest_encloser: &Name) -> Name {
    let qlabels = qname.num_labels() as usize;
    let closest_labels = closest_encloser.num_labels() as usize;
    qname.trim_to(closest_labels + 1.min(qlabels.saturating_sub(closest_labels)))
}

fn wildcard_name(name: &Name) -> Result<Name> {
    name.prepend_label("*").map_err(|err| {
        anyhow!(
            "failed to construct wildcard name for {}: {err}",
            name.to_utf8()
        )
    })
}

fn type_present_in_bitmap(
    type_bit_maps: impl Iterator<Item = RecordType>,
    expected: RecordType,
) -> bool {
    type_bit_maps
        .into_iter()
        .any(|record_type| record_type == expected)
}

fn nsec_covers_name(owner: &Name, next: &Name, target: &Name) -> bool {
    if target <= owner {
        return false;
    }

    if owner < next {
        target < next
    } else if owner > next {
        target > owner || target < next
    } else {
        false
    }
}

fn hash_nsec3_name(
    name: &Name,
    algorithm: Nsec3HashAlgorithm,
    salt: &[u8],
    iterations: u16,
) -> Result<Vec<u8>> {
    algorithm
        .hash(salt, name, iterations)
        .map(|hash| hash.as_ref().to_vec())
        .map_err(|err| anyhow!(err.to_string()))
}

fn nsec3_owner_hash(owner: &Name) -> Result<Vec<u8>> {
    let Some(label) = owner.iter().next() else {
        bail!("invalid NSEC3 owner name: {owner}");
    };
    BASE32_DNSSEC
        .decode(label)
        .map_err(|err| anyhow!("invalid NSEC3 owner hash {}: {err}", owner.to_utf8()))
}

fn nsec3_covers_hash(owner_hash: &[u8], next_hash: &[u8], target_hash: &[u8]) -> bool {
    if owner_hash < next_hash {
        target_hash > owner_hash && target_hash < next_hash
    } else if owner_hash > next_hash {
        target_hash > owner_hash || target_hash < next_hash
    } else {
        false
    }
}

pub fn verify_dnskey_with_ds(
    zone: &Name,
    dnskey_records: &[Record],
    ds_records: &[Record],
) -> Result<()> {
    let mut matched = false;
    for ds_record in ds_records {
        let Some(ds) = as_ds(ds_record) else {
            continue;
        };
        for dnskey_record in dnskey_records {
            let Some(dnskey) = as_dnskey(dnskey_record) else {
                continue;
            };
            if ds.key_tag()
                == dnskey
                    .calculate_key_tag()
                    .context("calculate dnskey key-tag")?
                && ds.algorithm() == dnskey.algorithm()
                && ds.covers(zone, dnskey).context("match ds to dnskey")?
            {
                matched = true;
                break;
            }
        }
    }

    if matched {
        Ok(())
    } else {
        bail!("no DS matched any DNSKEY for zone {zone}")
    }
}

pub fn verify_root_dnskeys(
    zone: &Name,
    dnskey_records: &[Record],
    rrsig_records: &[Record],
) -> Result<ValidatedKeys> {
    let trust_anchors = root_trust_anchors();
    verify_root_dnskeys_with_anchors(zone, dnskey_records, rrsig_records, &trust_anchors)
}

pub fn dnskey_rrset_matches_trust_anchors(
    dnskey_records: &[Record],
    trust_anchors: &TrustAnchors,
) -> bool {
    dnskey_records.iter().filter_map(as_dnskey).any(|dnskey| {
        dnskey
            .key()
            .ok()
            .map(|key| trust_anchors.contains(key.as_ref()))
            .unwrap_or(false)
    })
}

pub fn verify_root_dnskeys_with_anchors(
    zone: &Name,
    dnskey_records: &[Record],
    rrsig_records: &[Record],
    trust_anchors: &TrustAnchors,
) -> Result<ValidatedKeys> {
    if !dnskey_rrset_matches_trust_anchors(dnskey_records, trust_anchors) {
        bail!("root DNSKEY rrset is not anchored by local trust anchors")
    }

    verify_rrset(zone, dnskey_records, rrsig_records, dnskey_records)?;
    Ok(ValidatedKeys {
        zone: zone.clone(),
        keys: dnskey_records.to_vec(),
    })
}

pub fn verify_rrset(
    name: &Name,
    records: &[Record],
    rrsig_records: &[Record],
    candidate_keys: &[Record],
) -> Result<()> {
    if records.is_empty() {
        bail!("empty rrset for {name}")
    }

    let dns_class = records[0].dns_class();
    let now = now_unix();

    for rrsig_record in rrsig_records {
        let Some(rrsig) = as_rrsig(rrsig_record) else {
            continue;
        };
        if rrsig.sig_inception().get() > now || rrsig.sig_expiration().get() < now {
            continue;
        }

        for key_record in candidate_keys {
            let Some(dnskey) = as_dnskey(key_record) else {
                continue;
            };
            if dnskey.calculate_key_tag().context("calculate key tag")? != rrsig.key_tag() {
                continue;
            }
            if dnskey.algorithm() != rrsig.algorithm() {
                continue;
            }
            if key_record.name() != rrsig.signer_name() {
                continue;
            }
            if dnskey
                .verify_rrsig(name, dns_class, rrsig, records.iter())
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    bail!(
        "no valid RRSIG found for {name} {:?}",
        records[0].record_type()
    )
}

pub fn parent_zone(name: &Name) -> Option<Name> {
    if name.is_root() {
        return None;
    }
    let labels = name.iter().skip(1).collect::<Vec<_>>();
    Name::from_labels(labels)
        .ok()
        .or_else(|| Name::from_ascii(".").ok())
}

pub fn collect_rrset_records(
    message: &Message,
    name: &Name,
    record_type: RecordType,
) -> Vec<Record> {
    all_records(message)
        .filter(|record| record.name() == name && record.record_type() == record_type)
        .cloned()
        .collect()
}

pub fn collect_rrsig_records(message: &Message, name: &Name, covered: RecordType) -> Vec<Record> {
    all_records(message)
        .filter(|record| record.name() == name && record.record_type() == RecordType::RRSIG)
        .filter(|record| {
            as_rrsig(record)
                .map(|rrsig| rrsig.type_covered() == covered)
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

pub fn find_zone_signers(message: &Message) -> HashSet<Name> {
    all_records(message)
        .filter_map(as_rrsig)
        .map(|rrsig| rrsig.signer_name().clone())
        .collect()
}

fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(u64::from(u32::MAX)) as u32)
        .unwrap_or(0)
}

fn all_records(message: &Message) -> impl Iterator<Item = &Record> {
    message
        .answers()
        .iter()
        .chain(message.name_servers().iter())
        .chain(message.additionals().iter())
}

fn as_dnskey(record: &Record) -> Option<&DNSKEY> {
    match record.data() {
        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => Some(dnskey),
        _ => None,
    }
}

fn as_ds(record: &Record) -> Option<&DS> {
    match record.data() {
        RData::DNSSEC(DNSSECRData::DS(ds)) => Some(ds),
        _ => None,
    }
}

fn as_rrsig(record: &Record) -> Option<&RRSIG> {
    match record.data() {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => Some(rrsig),
        _ => None,
    }
}

fn as_nsec(record: &Record) -> Option<&NSEC> {
    match record.data() {
        RData::DNSSEC(DNSSECRData::NSEC(nsec)) => Some(nsec),
        _ => None,
    }
}

fn as_nsec3(record: &Record) -> Option<&NSEC3> {
    match record.data() {
        RData::DNSSEC(DNSSECRData::NSEC3(nsec3)) => Some(nsec3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use hickory_proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_proto::dnssec::{
        Algorithm, DigestType, PublicKey, PublicKeyBuf, SigSigner, SigningKey, TBS,
    };
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, NS};
    use hickory_proto::rr::{DNSClass, RData};

    struct SignedZone {
        zone: Name,
        dnskey_record: Record,
        signer: SigSigner,
    }

    fn new_signed_zone(zone: &str) -> SignedZone {
        let zone = Name::from_ascii(zone).expect("zone name");
        let algorithm = Algorithm::ECDSAP256SHA256;
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(algorithm).expect("pkcs8");
        let signing_key = EcdsaSigningKey::from_pkcs8(&pkcs8, algorithm).expect("signing key");
        let public_key = signing_key.to_public_key().expect("public key");
        let dnskey = DNSKEY::new(
            true,
            true,
            false,
            PublicKeyBuf::new(public_key.public_bytes().to_vec(), algorithm),
        );
        let dnskey_record = record(
            zone.clone(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        );
        let signer = SigSigner::dnssec(
            dnskey,
            Box::new(signing_key),
            zone.clone(),
            Duration::from_secs(300),
        );

        SignedZone {
            zone,
            dnskey_record,
            signer,
        }
    }

    fn record(name: Name, ttl: u32, data: RData) -> Record {
        let mut record = Record::from_rdata(name, ttl, data);
        record.set_dns_class(DNSClass::IN);
        record
    }

    fn now_window() -> (u32, u32) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix time")
            .as_secs() as u32;
        (now.saturating_sub(60), now.saturating_add(300))
    }

    fn sign_rrset(
        owner: &Name,
        ttl: u32,
        record_type: RecordType,
        signer: &SigSigner,
        rrset: &[Record],
    ) -> Record {
        let (inception, expiration) = now_window();
        let key_tag = signer.calculate_key_tag().expect("key tag");
        let pre_rrsig = RRSIG::new(
            record_type,
            signer.key().algorithm(),
            owner.num_labels(),
            ttl,
            expiration,
            inception,
            key_tag,
            signer.signer_name().clone(),
            Vec::new(),
        );
        let mut pre_record: Record<RRSIG> =
            Record::from_rdata(owner.clone(), ttl, pre_rrsig.clone());
        pre_record.set_dns_class(DNSClass::IN);
        let tbs = TBS::from_rrsig(&pre_record, rrset.iter()).expect("rrsig tbs");
        let signature = signer.sign(&tbs).expect("rrsig signature");
        record(
            owner.clone(),
            ttl,
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
                record_type,
                signer.key().algorithm(),
                owner.num_labels(),
                ttl,
                expiration,
                inception,
                key_tag,
                signer.signer_name().clone(),
                signature,
            ))),
        )
    }

    fn signed_rrset(owner: &Name, ttl: u32, signer: &SigSigner, rrset: Vec<Record>) -> Vec<Record> {
        let mut records = rrset;
        let record_type = records[0].record_type();
        let rrsig = sign_rrset(owner, ttl, record_type, signer, &records);
        records.push(rrsig);
        records
    }

    fn message_with_answers(qname: &Name, qtype: RecordType, answers: Vec<Record>) -> Message {
        let mut message = Message::new();
        message
            .set_id(77)
            .set_message_type(MessageType::Response)
            .set_recursion_desired(true)
            .set_recursion_available(true)
            .add_query(Query::query(qname.clone(), qtype))
            .add_answers(answers);
        message
    }

    fn message_with_authority(
        qname: &Name,
        qtype: RecordType,
        rcode: ResponseCode,
        authority: Vec<Record>,
    ) -> Message {
        let mut message = Message::new();
        message
            .set_id(88)
            .set_message_type(MessageType::Response)
            .set_response_code(rcode)
            .add_query(Query::query(qname.clone(), qtype))
            .add_name_servers(authority);
        message
    }

    fn nsec3_owner_name(zone: &Name, hash: &[u8]) -> Name {
        let encoded = BASE32_DNSSEC.encode(hash);
        Name::from_ascii(format!("{encoded}.{}", zone.to_ascii())).expect("nsec3 owner")
    }

    #[test]
    fn verifies_signed_answer_rrset() {
        let zone = new_signed_zone("example.com.");
        let owner = Name::from_ascii("www.example.com.").expect("owner");
        let answer = record(owner.clone(), 300, RData::A(A::new(192, 0, 2, 1)));
        let message = message_with_answers(
            &owner,
            RecordType::A,
            signed_rrset(&owner, 300, &zone.signer, vec![answer]),
        );

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record.clone()],
        };
        let state = verify_message_rrsets(&message, &validated).expect("validate rrset");

        assert_eq!(state, ValidationState::Secure);
    }

    #[test]
    fn matches_dnskey_with_parent_ds() {
        let child = new_signed_zone("example.com.");
        let dnskey = as_dnskey(&child.dnskey_record).expect("dnskey");
        let ds = DS::new(
            dnskey.calculate_key_tag().expect("key tag"),
            dnskey.algorithm(),
            DigestType::SHA256,
            dnskey
                .to_digest(&child.zone, DigestType::SHA256)
                .expect("dnskey digest")
                .as_ref()
                .to_vec(),
        );
        let ds_record = record(child.zone.clone(), 300, RData::DNSSEC(DNSSECRData::DS(ds)));

        verify_dnskey_with_ds(&child.zone, &[child.dnskey_record], &[ds_record])
            .expect("dnskey covered by ds");
    }

    #[test]
    fn verifies_root_dnskeys_with_custom_anchor() {
        let root = new_signed_zone(".");
        let dnskey_rrset = signed_rrset(
            &root.zone,
            300,
            &root.signer,
            vec![root.dnskey_record.clone()],
        );
        let anchors = {
            let mut anchors = TrustAnchors::empty();
            let dnskey = as_dnskey(&root.dnskey_record).expect("root dnskey");
            anchors.insert(dnskey.key().expect("root public key").as_ref());
            anchors
        };

        let validated = verify_root_dnskeys_with_anchors(
            &root.zone,
            &dnskey_rrset[..1],
            &dnskey_rrset[1..],
            &anchors,
        )
        .expect("root dnskeys validated");

        assert_eq!(validated.zone, root.zone);
        assert_eq!(validated.keys.len(), 1);
    }

    #[test]
    fn validates_nsec_nodata_response() {
        let zone = new_signed_zone("example.com.");
        let qname = Name::from_ascii("ns1.example.com.").expect("qname");
        let nsec = record(
            qname.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::from_ascii("ns2.example.com.").expect("next name"),
                [RecordType::A, RecordType::RRSIG, RecordType::NSEC],
            ))),
        );
        let authority = signed_rrset(&qname, 300, &zone.signer, vec![nsec]);
        let message =
            message_with_authority(&qname, RecordType::MX, ResponseCode::NoError, authority);

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record.clone()],
        };

        let state = verify_message_rrsets(&message, &validated).expect("validate nsec nodata");
        assert_eq!(state, ValidationState::Secure);
    }

    #[test]
    fn validates_nsec_nxdomain_response() {
        let zone = new_signed_zone("example.com.");
        let qname = Name::from_ascii("missing.example.com.").expect("qname");

        let cover_qname = record(
            Name::from_ascii("example.com.").expect("owner"),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::from_ascii("zzz.example.com.").expect("next"),
                [
                    RecordType::SOA,
                    RecordType::NS,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                ],
            ))),
        );

        let cover_qname_owner = cover_qname.name().clone();
        let authority = signed_rrset(&cover_qname_owner, 300, &zone.signer, vec![cover_qname]);
        let message =
            message_with_authority(&qname, RecordType::A, ResponseCode::NXDomain, authority);

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record.clone()],
        };

        let state = verify_message_rrsets(&message, &validated).expect("validate nsec nxdomain");
        assert_eq!(state, ValidationState::Secure);
    }

    #[test]
    fn validates_nsec3_nodata_response() {
        let zone = new_signed_zone("example.com.");
        let qname = Name::from_ascii("ns1.example.com.").expect("qname");
        let salt = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let qhash =
            hash_nsec3_name(&qname, Nsec3HashAlgorithm::SHA1, &salt, 1).expect("hash qname");
        let next_hash = hash_nsec3_name(
            &Name::from_ascii("ns2.example.com.").expect("next name"),
            Nsec3HashAlgorithm::SHA1,
            &salt,
            1,
        )
        .expect("hash next");
        let owner = nsec3_owner_name(&zone.zone, &qhash);
        let nsec3 = record(
            owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                1,
                salt.clone(),
                next_hash,
                [RecordType::A, RecordType::RRSIG],
            ))),
        );
        let authority = signed_rrset(&owner, 300, &zone.signer, vec![nsec3]);
        let message =
            message_with_authority(&qname, RecordType::MX, ResponseCode::NoError, authority);

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record.clone()],
        };

        let state = verify_message_rrsets(&message, &validated).expect("validate nsec3 nodata");
        assert_eq!(state, ValidationState::Secure);
    }

    #[test]
    fn validates_nsec3_nxdomain_response() {
        let zone = new_signed_zone("example.com.");
        let qname = Name::from_ascii("missing.example.com.").expect("qname");
        let closest = Name::from_ascii("example.com.").expect("closest");
        let next_closer = Name::from_ascii("missing.example.com.").expect("next closer");
        let wildcard = Name::from_ascii("*.example.com.").expect("wildcard");
        let salt = vec![0x10, 0x20, 0x30, 0x40];

        let closest_hash =
            hash_nsec3_name(&closest, Nsec3HashAlgorithm::SHA1, &salt, 1).expect("closest hash");
        let next_closer_hash = hash_nsec3_name(&next_closer, Nsec3HashAlgorithm::SHA1, &salt, 1)
            .expect("next closer hash");
        let wildcard_hash =
            hash_nsec3_name(&wildcard, Nsec3HashAlgorithm::SHA1, &salt, 1).expect("wildcard hash");
        let zero_hash = vec![0u8; next_closer_hash.len()];
        let max_hash = vec![0xFFu8; next_closer_hash.len()];

        let ce_owner = nsec3_owner_name(&zone.zone, &closest_hash);
        let cover_owner = nsec3_owner_name(&zone.zone, &zero_hash);

        let ce_record = record(
            ce_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                1,
                salt.clone(),
                next_closer_hash.clone(),
                [RecordType::SOA, RecordType::NS, RecordType::RRSIG],
            ))),
        );
        assert!(next_closer_hash > zero_hash && next_closer_hash < max_hash);
        assert!(wildcard_hash > zero_hash && wildcard_hash < max_hash);
        let covering_record = record(
            cover_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                1,
                salt.clone(),
                max_hash,
                [RecordType::SOA, RecordType::NS, RecordType::RRSIG],
            ))),
        );

        let mut authority = signed_rrset(&ce_owner, 300, &zone.signer, vec![ce_record]);
        authority.extend(signed_rrset(
            &cover_owner,
            300,
            &zone.signer,
            vec![covering_record],
        ));
        let message =
            message_with_authority(&qname, RecordType::A, ResponseCode::NXDomain, authority);

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record],
        };

        let state = verify_message_rrsets(&message, &validated).expect("validate nsec3 nxdomain");
        assert_eq!(state, ValidationState::Secure);
    }

    #[test]
    fn validates_nsec_wildcard_nodata_response() {
        let zone = new_signed_zone("example.com.");
        let qname = Name::from_ascii("a.z.w.example.com.").expect("qname");
        let wildcard = Name::from_ascii("*.w.example.com.").expect("wildcard");
        let covering_owner = Name::from_ascii("x.y.w.example.com.").expect("owner");

        let wildcard_nsec = record(
            wildcard.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::from_ascii("x.w.example.com.").expect("next"),
                [RecordType::MX, RecordType::RRSIG, RecordType::NSEC],
            ))),
        );
        let covering_nsec = record(
            covering_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
                Name::from_ascii("xx.example.com.").expect("next"),
                [RecordType::MX, RecordType::RRSIG, RecordType::NSEC],
            ))),
        );

        let mut authority = signed_rrset(&wildcard, 300, &zone.signer, vec![wildcard_nsec]);
        authority.extend(signed_rrset(
            &covering_owner,
            300,
            &zone.signer,
            vec![covering_nsec],
        ));
        let message =
            message_with_authority(&qname, RecordType::AAAA, ResponseCode::NoError, authority);

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record.clone()],
        };

        let state =
            verify_message_rrsets(&message, &validated).expect("validate nsec wildcard nodata");
        assert_eq!(state, ValidationState::Secure);
    }

    #[test]
    fn validates_nsec3_wildcard_nodata_response() {
        let zone = new_signed_zone("example.com.");
        let qname = Name::from_ascii("a.z.w.example.com.").expect("qname");
        let closest = Name::from_ascii("w.example.com.").expect("closest");
        let wildcard = Name::from_ascii("*.w.example.com.").expect("wildcard");
        let next_closer = Name::from_ascii("z.w.example.com.").expect("next closer");
        let salt = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let closest_hash =
            hash_nsec3_name(&closest, Nsec3HashAlgorithm::SHA1, &salt, 1).expect("closest hash");
        let wildcard_hash =
            hash_nsec3_name(&wildcard, Nsec3HashAlgorithm::SHA1, &salt, 1).expect("wildcard hash");
        let next_closer_hash = hash_nsec3_name(&next_closer, Nsec3HashAlgorithm::SHA1, &salt, 1)
            .expect("next closer hash");
        let zero_hash = vec![0u8; next_closer_hash.len()];
        let max_hash = vec![0xFFu8; next_closer_hash.len()];

        let ce_owner = nsec3_owner_name(&zone.zone, &closest_hash);
        let wildcard_owner = nsec3_owner_name(&zone.zone, &wildcard_hash);
        let cover_owner = nsec3_owner_name(&zone.zone, &zero_hash);

        let ce_record = record(
            ce_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                1,
                salt.clone(),
                wildcard_hash.clone(),
                [],
            ))),
        );
        let wildcard_record = record(
            wildcard_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                1,
                salt.clone(),
                max_hash.clone(),
                [RecordType::MX, RecordType::RRSIG],
            ))),
        );
        let covering_record = record(
            cover_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                1,
                salt.clone(),
                max_hash,
                [RecordType::SOA, RecordType::NS, RecordType::RRSIG],
            ))),
        );

        assert!(
            next_closer_hash > zero_hash && next_closer_hash < vec![0xFFu8; next_closer_hash.len()]
        );

        let mut authority = signed_rrset(&ce_owner, 300, &zone.signer, vec![ce_record]);
        authority.extend(signed_rrset(
            &wildcard_owner,
            300,
            &zone.signer,
            vec![wildcard_record],
        ));
        authority.extend(signed_rrset(
            &cover_owner,
            300,
            &zone.signer,
            vec![covering_record],
        ));
        let message =
            message_with_authority(&qname, RecordType::AAAA, ResponseCode::NoError, authority);

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record.clone()],
        };

        let state =
            verify_message_rrsets(&message, &validated).expect("validate nsec3 wildcard nodata");
        assert_eq!(state, ValidationState::Secure);
    }

    #[test]
    fn validates_nsec3_ds_child_zone_nodata_response() {
        let zone = new_signed_zone("example.com.");
        let qname = zone.zone.clone();
        let salt = vec![0x10, 0x20, 0x30, 0x40];
        let qhash = hash_nsec3_name(&qname, Nsec3HashAlgorithm::SHA1, &salt, 1).expect("qhash");
        let next_hash = hash_nsec3_name(
            &Name::from_ascii("ns1.example.com.").expect("next name"),
            Nsec3HashAlgorithm::SHA1,
            &salt,
            1,
        )
        .expect("next hash");
        let owner = nsec3_owner_name(&zone.zone, &qhash);
        let nsec3 = record(
            owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                1,
                salt,
                next_hash,
                [
                    RecordType::SOA,
                    RecordType::NS,
                    RecordType::DNSKEY,
                    RecordType::RRSIG,
                ],
            ))),
        );
        let authority = signed_rrset(&owner, 300, &zone.signer, vec![nsec3]);
        let message =
            message_with_authority(&qname, RecordType::DS, ResponseCode::NoError, authority);

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record.clone()],
        };

        let state =
            verify_message_rrsets(&message, &validated).expect("validate nsec3 ds child nodata");
        assert_eq!(state, ValidationState::Secure);
    }

    #[test]
    fn validates_nsec3_optout_ds_nodata_as_insecure() {
        let zone = new_signed_zone("example.com.");
        let qname = Name::from_ascii("c.example.com.").expect("qname");
        let closest = zone.zone.clone();
        let salt = vec![0x01, 0x23, 0x45, 0x67];

        let closest_hash =
            hash_nsec3_name(&closest, Nsec3HashAlgorithm::SHA1, &salt, 1).expect("closest hash");
        let next_closer_hash =
            hash_nsec3_name(&qname, Nsec3HashAlgorithm::SHA1, &salt, 1).expect("next closer hash");
        let zero_hash = vec![0u8; next_closer_hash.len()];
        let max_hash = vec![0xFFu8; next_closer_hash.len()];

        let ce_owner = nsec3_owner_name(&zone.zone, &closest_hash);
        let cover_owner = nsec3_owner_name(&zone.zone, &zero_hash);

        let ce_record = record(
            ce_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                1,
                salt.clone(),
                next_closer_hash.clone(),
                [
                    RecordType::SOA,
                    RecordType::NS,
                    RecordType::DNSKEY,
                    RecordType::RRSIG,
                ],
            ))),
        );
        let cover_record = record(
            cover_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                true,
                1,
                salt,
                max_hash,
                [RecordType::SOA, RecordType::NS, RecordType::RRSIG],
            ))),
        );

        assert!(
            next_closer_hash > zero_hash && next_closer_hash < vec![0xFFu8; next_closer_hash.len()]
        );

        let mut authority = signed_rrset(&ce_owner, 300, &zone.signer, vec![ce_record]);
        authority.extend(signed_rrset(
            &cover_owner,
            300,
            &zone.signer,
            vec![cover_record],
        ));
        let message =
            message_with_authority(&qname, RecordType::DS, ResponseCode::NoError, authority);

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record.clone()],
        };

        let state = verify_message_rrsets(&message, &validated).expect("validate optout ds nodata");
        assert_eq!(state, ValidationState::Insecure);
    }

    #[test]
    fn validates_nsec3_optout_referral_as_insecure() {
        let zone = new_signed_zone("example.com.");
        let qname = Name::from_ascii("mc.c.example.com.").expect("qname");
        let delegation = Name::from_ascii("c.example.com.").expect("delegation");
        let closest = zone.zone.clone();
        let salt = vec![0x89, 0xAB, 0xCD, 0xEF];

        let closest_hash =
            hash_nsec3_name(&closest, Nsec3HashAlgorithm::SHA1, &salt, 1).expect("closest hash");
        let delegation_hash = hash_nsec3_name(&delegation, Nsec3HashAlgorithm::SHA1, &salt, 1)
            .expect("delegation hash");
        let zero_hash = vec![0u8; delegation_hash.len()];
        let max_hash = vec![0xFFu8; delegation_hash.len()];

        let ce_owner = nsec3_owner_name(&zone.zone, &closest_hash);
        let cover_owner = nsec3_owner_name(&zone.zone, &zero_hash);

        let ce_record = record(
            ce_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                1,
                salt.clone(),
                delegation_hash.clone(),
                [
                    RecordType::SOA,
                    RecordType::NS,
                    RecordType::DNSKEY,
                    RecordType::RRSIG,
                ],
            ))),
        );
        let cover_record = record(
            cover_owner.clone(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                true,
                1,
                salt,
                max_hash,
                [RecordType::SOA, RecordType::NS, RecordType::RRSIG],
            ))),
        );

        assert!(
            delegation_hash > zero_hash && delegation_hash < vec![0xFFu8; delegation_hash.len()]
        );

        let ns1 = record(
            delegation.clone(),
            300,
            RData::NS(NS(Name::from_ascii("ns1.c.example.com.").expect("ns1"))),
        );
        let ns2 = record(
            delegation.clone(),
            300,
            RData::NS(NS(Name::from_ascii("ns2.c.example.com.").expect("ns2"))),
        );
        let mut authority = vec![ns1, ns2];
        authority.extend(signed_rrset(&ce_owner, 300, &zone.signer, vec![ce_record]));
        authority.extend(signed_rrset(
            &cover_owner,
            300,
            &zone.signer,
            vec![cover_record],
        ));
        let message =
            message_with_authority(&qname, RecordType::MX, ResponseCode::NoError, authority);

        let validated = ValidatedKeys {
            zone: zone.zone.clone(),
            keys: vec![zone.dnskey_record],
        };

        let state = verify_message_rrsets(&message, &validated).expect("validate optout referral");
        assert_eq!(state, ValidationState::Insecure);
    }
}
