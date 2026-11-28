//! Dedicated directory-only adjacency profile. Never used on a business
//! listener or negotiated by guessing from a timeout or a frame.

use boreas_proto::{messages::DirectoryPage, objects};

use super::*;

const MAX_FORWARDED: usize = 14; // 16 slots minus the two authenticated endpoints.
const PAGE_PREFIX: usize = 12; // subtype, u64 page_seq, count, u16 object length.

impl MeshProbe<'_> {
    /// Run one bounded directory exchange with an adjacent Core. All member
    /// identities come from local configuration; only CoreLSAs cross the wire.
    /// The authenticated socket is closed, never returned for business I/O.
    pub fn sync_directory(
        &mut self,
        candidate: Candidate<'_>,
        members: &[&[u8]],
        outer: &dyn Fn() -> Result<OpenSslOuterTlsConnector, TunnelError>,
        admission: &Admission,
    ) -> Result<(), Error> {
        let members = self.directory_members(members)?;
        let peer = self.verified_core(candidate.signed_identity)?;
        require_member(&members, &peer)?;
        let link = self.dial_for(&[candidate], outer, admission, HopPurpose::Directory)?;
        self.exchange_directory(link, &members, true)
    }

    /// Server half for a dedicated directory-only socket from an expected Core.
    pub fn accept_directory(
        &mut self,
        socket: TcpStream,
        signed_peer_identity: &[u8],
        members: &[&[u8]],
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
    ) -> Result<(), Error> {
        let members = self.directory_members(members)?;
        let peer = self.verified_core(signed_peer_identity)?;
        require_member(&members, &peer)?;
        let link = self.accept_for(
            socket,
            signed_peer_identity,
            outer,
            admission,
            HopPurpose::Directory,
        )?;
        self.exchange_directory(link, &members, false)
    }

    /// Accept a directory session from any provisioned member on one socket.
    /// Inner mTLS resolves the exact SPKI from signed membership; only then
    /// is the normal exact-peer SessionHello policy constructed. No in-band
    /// hint is trusted to select a member, and the socket cannot serve business.
    pub fn accept_directory_member(
        &mut self,
        socket: TcpStream,
        members: &[&[u8]],
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
    ) -> Result<u8, Error> {
        self.poll_identity_mailbox()?;
        let deadline = self.deadline(&self.local.clone())?;
        let members = self.directory_members(members)?;
        let extractor = Arc::new(PkiIdentityExtractor::new(
            members.values().map(|core| core.identity.clone()).collect(),
        )?);
        let pq_identity = PqWgIdentity::from_private_key_pem(&self.pem.private_key_pem)
            .map_err(|_| Error::Identity)?;
        let server = LinkServer::new(Box::new(
            PqWgInnerAcceptor::new(pq_identity, Policy::production_default(), extractor)
                .map_err(|_| Error::Identity)?,
        ));
        let control_socket = socket.try_clone().map_err(TunnelError::from)?;
        let mut selected = None;
        let accepted = server.accept_tls_stream_with_policy(
            socket,
            outer,
            deadline,
            admission,
            |authenticated| {
                let peer = members
                    .values()
                    .find(|core| core.peer() == authenticated)
                    .ok_or(TunnelError::Unsupported("unprovisioned directory peer"))?;
                self.check(peer)
                    .map_err(|_| TunnelError::Unsupported("directory peer not current"))?;
                selected = Some(peer.clone());
                Ok(SessionPolicy::default_pq768(self.local(), peer.peer()))
            },
        )?;
        let peer = selected.ok_or(Error::Identity)?;
        let id = peer.id;
        let link = self.accept_advertisements(
            accepted,
            control_socket,
            peer,
            HopPurpose::Directory,
            deadline,
        )?;
        self.exchange_directory(link, &members, false)?;
        Ok(id)
    }

    /// Resolve the signed slot for a locally configured member before using
    /// its file position to bind a dedicated listener or dial target.
    pub fn directory_member_id(&mut self, signed: &[u8]) -> Result<u8, Error> {
        Ok(self.verified_core(signed)?.id)
    }

    fn directory_members(&mut self, signed: &[&[u8]]) -> Result<BTreeMap<u8, Core>, Error> {
        if signed.len() > MAX_FORWARDED + 1 {
            return Err(Error::Identity);
        }
        let mut members = BTreeMap::new();
        for raw in signed {
            let core = self.verified_core(raw)?;
            if core.id == self.local.id || members.insert(core.id, core).is_some() {
                return Err(Error::Identity);
            }
        }
        Ok(members)
    }

    fn exchange_directory(
        &mut self,
        mut link: Adjacency,
        members: &BTreeMap<u8, Core>,
        initiator: bool,
    ) -> Result<(), Error> {
        let deadline = link.attempt_until.min(self.route_deadline(&[], &[&link])?);
        let socket = link.socket.try_clone().map_err(TunnelError::from)?;
        let mut local_error = None;
        let result = bounded_link_operation(&socket, deadline, || {
            let outcome = (|| -> Result<(), Error> {
                if initiator {
                    self.send_directory(&mut link, members)?;
                    self.recv_directory(&mut link, members)?;
                } else {
                    self.recv_directory(&mut link, members)?;
                    self.send_directory(&mut link, members)?;
                }
                self.check_directory_link(&link)?;
                Ok(())
            })();
            match outcome {
                Ok(()) => Ok(()),
                Err(Error::Transport(e)) => Err(e),
                Err(e) => {
                    local_error = Some(e);
                    Err(TunnelError::Unsupported("Core directory exchange rejected"))
                }
            }
        });
        if let Some(e) = local_error {
            return Err(e);
        }
        result.map_err(Error::from)
    }

    fn check_directory_link(&mut self, link: &Adjacency) -> Result<(), Error> {
        self.check_route_utc(std::slice::from_ref(&link.peer), link.remote_lsa_expiry)
    }

    fn send_directory(
        &mut self,
        link: &mut Adjacency,
        members: &BTreeMap<u8, Core>,
    ) -> Result<(), Error> {
        let mut ordinal = 0;
        for (&id, origin) in members {
            if id == link.peer.id || !self.remote_lsas.contains_key(&id) {
                continue;
            }
            self.check_directory_link(link)?;
            let Ok(now) = self.check(origin) else {
                continue;
            };
            let head = &self.remote_lsas[&id];
            if !self.trust.is_current_core_lsa(id, head.object_id())
                || lsa(head, id, now).is_err()
                || head.raw_signed_object().len() >= ControlType::Lsa.body_cap()
            {
                continue;
            }
            send_page(&mut link.session, ordinal, head.raw_signed_object())?;
            ordinal += 1;
        }
        self.check_directory_link(link)?;
        // Every nonempty page carries one envelope. Repeat the exact direct
        // advertisement as an unambiguous end marker, even for an empty batch.
        send_page(
            &mut link.session,
            ordinal,
            self.local_lsa.raw_signed_object(),
        )?;
        Ok(())
    }

    fn recv_directory(
        &mut self,
        link: &mut Adjacency,
        members: &BTreeMap<u8, Core>,
    ) -> Result<(), Error> {
        let mut seen = 0u32;
        for ordinal in 0..=MAX_FORWARDED {
            let body = recv_control(&mut link.session, ControlType::DirectoryPage)?;
            self.check_directory_link(link)?;
            let (id, raw) = parse_page(&body, ordinal as u64)?;
            if id == link.peer.id {
                return if raw == link.report().signed_lsa.as_slice() {
                    Ok(())
                } else {
                    Err(Error::Lsa)
                };
            }
            let origin = members.get(&id).ok_or(Error::Lsa)?;
            let bit = 1u32 << id; // only configured, verified slots 1..=16.
            if ordinal == MAX_FORWARDED || seen & bit != 0 {
                return Err(Error::Lsa);
            }
            seen |= bit;
            let now = match self.check(origin) {
                Ok(now) => now,
                Err(error) if error.member_denial() => {
                    self.check_local_identity_denial()?;
                    self.check_directory_link(link)?;
                    // A healthy peer may not yet know a committed denial
                    // (for example, its signed carrier is no longer fresh).
                    // Never install a denied origin's LSA, but keep exchanging
                    // other heads over this still-authorized adjacency.
                    continue;
                }
                Err(e) => return Err(e),
            };
            match self.trust.verify_core_lsa(raw, id, now) {
                Ok(object) if !object.is_duplicate() => {
                    self.remote_lsas.insert(id, object);
                }
                // The original head stays byte-for-byte unchanged; neither
                // case sets a new deadline or advances the replay watermark.
                Ok(_) | Err(ManagementError::StaleSequence) => (),
                Err(e) => return Err(map_lsa_error(e, self.durable)),
            }
        }
        Err(Error::Lsa)
    }
}

fn require_member(members: &BTreeMap<u8, Core>, peer: &Core) -> Result<(), Error> {
    if members
        .get(&peer.id)
        .is_some_and(|m| m.object_id == peer.object_id)
    {
        Ok(())
    } else {
        Err(Error::Identity)
    }
}

fn send_page(
    session: &mut EstablishedSession,
    ordinal: u64,
    raw: &[u8],
) -> Result<(), TunnelError> {
    if raw.len() >= ControlType::Lsa.body_cap() {
        return Err(TunnelError::Unsupported("Core directory page too large"));
    }
    let mut body = Vec::with_capacity(PAGE_PREFIX + raw.len());
    body.push(ControlType::DirectoryPage as u8);
    body.extend_from_slice(&ordinal.to_be_bytes());
    body.push(1);
    body.extend_from_slice(&(raw.len() as u16).to_be_bytes());
    body.extend_from_slice(raw);
    session.send_control(ControlType::DirectoryPage, &body)
}

fn parse_page(body: &[u8], ordinal: u64) -> Result<(u8, &[u8]), Error> {
    let raw = body.get(PAGE_PREFIX..).ok_or(Error::Lsa)?;
    if raw.len() >= ControlType::Lsa.body_cap() {
        return Err(Error::Lsa);
    }
    let page = DirectoryPage::decode(body).map_err(|_| Error::Lsa)?;
    if page.page_seq != ordinal || page.objects.len() != 1 {
        return Err(Error::Lsa);
    }
    let object = objects::decode_tbs(&page.objects[0].raw_tbs).map_err(|_| Error::Lsa)?;
    let ObjectBody::CoreLsa(lsa) = object.body else {
        return Err(Error::Lsa);
    };
    // The unchanged one-object DirectoryPage format has checked the length
    // and full body consumption. Hand the original bytes to the verifier.
    Ok((lsa.core_id, raw))
}
