// L3 smuggling test proxy: forwards everything to the Go backend on
// 127.0.0.1:8899, listening on 0.0.0.0:8898. Pipelining is toggled by the
// L3_PIPELINING env var ("1" = on) so we can test both code paths.

use async_trait::async_trait;

use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{ProxyHttp, Session};

pub struct L3Gateway {
    pipelining: bool,
}

#[async_trait]
impl ProxyHttp for L3Gateway {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn early_request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<()> {
        if self.pipelining {
            session.set_pipelining_enabled(true);
        }
        Ok(())
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        Ok(Box::new(HttpPeer::new(
            ("127.0.0.1", 8899),
            false,
            "127.0.0.1".into(),
        )))
    }
}

fn main() {
    env_logger::init();
    let pipelining = std::env::var("L3_PIPELINING").as_deref() == Ok("1");

    let opt = Opt::parse_args();
    let mut my_server = Server::new(Some(opt)).unwrap();
    my_server.bootstrap();

    let mut my_proxy =
        pingora_proxy::http_proxy_service(&my_server.configuration, L3Gateway { pipelining });
    my_proxy.add_tcp("0.0.0.0:8898");
    my_server.add_service(my_proxy);

    my_server.run_forever();
}
