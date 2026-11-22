//! Shared ingress for the explicit routed business profile. No wire slot or
//! address can select the adjacent identity before inner TLS authenticates it.

use super::*;

impl MeshProbe<'_> {
    pub(crate) fn accept_routed_neighbor(
        &mut self,
        tcp: TcpStream,
        neighbors: &[(Core, [u8; 32])],
        outer: &OpenSslOuterTlsAcceptor,
        admission: &Admission,
        until: Instant,
    ) -> Result<Adjacency, Error> {
        self.poll_identity_mailbox()?;
        if neighbors.is_empty() {
            return Err(Error::NoRoute);
        }
        let local = self.local.clone();
        let deadline = until.min(self.deadline(&local)?);
        let extractor = Arc::new(PkiIdentityExtractor::new(
            neighbors
                .iter()
                .map(|(core, _)| core.identity.clone())
                .collect(),
        )?);
        let inner = OpenSslAcceptor::from_pem_identity(self.pem, Policy::production_default())
            .map_err(|_| Error::Identity)?;
        let server = LinkServer::new(Box::new(OpenSslInnerAcceptor::new(inner, extractor)));
        let control_socket = tcp.try_clone().map_err(TunnelError::from)?;
        let mut selected = None;
        let accepted = server.accept_tls_stream_with_policy(
            tcp,
            outer,
            deadline,
            admission,
            |authenticated| {
                let (peer, _) = neighbors
                    .iter()
                    .find(|(core, _)| core.peer() == authenticated)
                    .ok_or(TunnelError::Unsupported("unprovisioned routed neighbor"))?;
                self.check(peer)
                    .map_err(|_| TunnelError::Unsupported("routed neighbor not current"))?;
                selected = Some(peer.id);
                Ok(SessionPolicy::default_pq768(self.local(), peer.peer()))
            },
        )?;
        let (peer, head) = neighbors
            .iter()
            .find(|(core, _)| Some(core.id) == selected)
            .ok_or(Error::Identity)?;
        self.accept_advertisements(
            accepted,
            control_socket,
            peer.clone(),
            HopPurpose::Business(Some((deadline, *head))),
            deadline,
        )
    }
}
